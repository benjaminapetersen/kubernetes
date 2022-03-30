/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package clusterauthenticationtrust

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"reflect"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/authentication/request/headerrequest"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

const (
	configMapNamespace = "kube-system"
	configMapName      = "extension-apiserver-authentication"
)

// Controller holds the running state for the controller
type Controller struct {
	requiredAuthenticationData ClusterAuthenticationInfo

	configMapLister corev1listers.ConfigMapLister
	configMapClient corev1client.ConfigMapsGetter
	namespaceClient corev1client.NamespacesGetter

	// queue is where incoming work is placed to de-dup and to allow "easy" rate limited requeues on errors.
	// we only ever place one entry in here, but it is keyed as usual: namespace/name
	queue workqueue.RateLimitingInterface

	// kubeSystemConfigMapInformer is tracked so that we can start these on Run
	kubeSystemConfigMapInformer cache.SharedIndexInformer

	// preRunCaches are the caches to sync before starting the work of this control loop
	preRunCaches []cache.InformerSynced
}

// ClusterAuthenticationInfo holds the information that will included in public configmap.
type ClusterAuthenticationInfo struct {
	// ClientCA is the CA that can be used to verify the identity of normal clients
	ClientCA dynamiccertificates.CAContentProvider
	// RequestHeaderUsernameHeaders are the headers used by this kube-apiserver to determine username
	RequestHeaderUsernameHeaders headerrequest.StringSliceProvider

	// TODO (BEN): update this. and then delete the extra spaces :)
	//   - KEEP LOOKING FOR RequestHeaderUsernameHeaders (ctrl+click) and find all usages
	//     and make sure that all of them have RequestHeaderUIDHeaders also.
	//     I believe I already did the ones in code, just have the tests to update now.
	// RequestHeaderUsernameHeaders are the headers used by this kube-apiserver to determine username
	RequestHeaderUIDHeaders headerrequest.StringSliceProvider

	// RequestHeaderGroupHeaders are the headers used by this kube-apiserver to determine groups
	RequestHeaderGroupHeaders headerrequest.StringSliceProvider
	// RequestHeaderExtraHeaderPrefixes are the headers used by this kube-apiserver to determine user.extra
	RequestHeaderExtraHeaderPrefixes headerrequest.StringSliceProvider
	// RequestHeaderAllowedNames are the sujbects allowed to act as a front proxy
	RequestHeaderAllowedNames headerrequest.StringSliceProvider
	// RequestHeaderCA is the CA that can be used to verify the front proxy
	RequestHeaderCA dynamiccertificates.CAContentProvider
}

// NewClusterAuthenticationTrustController returns a controller that will maintain the kube-system configmap/extension-apiserver-authentication
// that holds information about how aggregated apiservers are recommended (but not required) to configure themselves.
func NewClusterAuthenticationTrustController(requiredAuthenticationData ClusterAuthenticationInfo, kubeClient kubernetes.Interface) *Controller {
	// TODO (BEN/MO): fix this, the metadata.name filter is missing
	// we construct our own informer because we need such a small subset of the information available.  Just one namespace.
	kubeSystemConfigMapInformer := corev1informers.NewConfigMapInformer(kubeClient, configMapNamespace, 12*time.Hour, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})

	// TODO (BEN): log stuff to see what we get
	// - output in tests does indeed show the wiring is correct, we see some output.
	// this at leasts proves the contorller was initialized, even if it was not run.
	// but we also see:
	//     I0128 10:10:56.020809    5680 cluster_authentication_trust_controller.go:468] Starting cluster_authentication_trust_controller controller
	// so it was run
	klog.ErrorS(fmt.Errorf("foo 🦄 🦄 🦄"), "Wheeeeeeeee 🦄 🦄 🦄",
		"info", requiredAuthenticationData,
		"uid", requiredAuthenticationData.RequestHeaderUIDHeaders.Value(),
		"username", requiredAuthenticationData.RequestHeaderUsernameHeaders.Value(),
		"group", requiredAuthenticationData.RequestHeaderGroupHeaders.Value(),
		"prefixes", requiredAuthenticationData.RequestHeaderExtraHeaderPrefixes.Value(),
		"allowed names", requiredAuthenticationData.RequestHeaderAllowedNames.Value(),
		"header CA", string(requiredAuthenticationData.RequestHeaderCA.CurrentCABundleContent()),
		"clientCA", string(requiredAuthenticationData.ClientCA.CurrentCABundleContent()))

	c := &Controller{
		requiredAuthenticationData:  requiredAuthenticationData,
		configMapLister:             corev1listers.NewConfigMapLister(kubeSystemConfigMapInformer.GetIndexer()),
		configMapClient:             kubeClient.CoreV1(),
		namespaceClient:             kubeClient.CoreV1(),
		queue:                       workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "cluster_authentication_trust_controller"),
		preRunCaches:                []cache.InformerSynced{kubeSystemConfigMapInformer.HasSynced},
		kubeSystemConfigMapInformer: kubeSystemConfigMapInformer,
	}

	kubeSystemConfigMapInformer.AddEventHandler(cache.FilteringResourceEventHandler{
		FilterFunc: func(obj interface{}) bool {
			if cast, ok := obj.(*corev1.ConfigMap); ok {
				return cast.Name == configMapName
			}
			if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				if cast, ok := tombstone.Obj.(*corev1.ConfigMap); ok {
					return cast.Name == configMapName
				}
			}
			return true // always return true just in case.  The checks are fairly cheap
		},
		Handler: cache.ResourceEventHandlerFuncs{
			// we have a filter, so any time we're called, we may as well queue. We only ever check one configmap
			// so we don't have to be choosy about our key.
			AddFunc: func(obj interface{}) {
				c.queue.Add(keyFn())
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				c.queue.Add(keyFn())
			},
			DeleteFunc: func(obj interface{}) {
				c.queue.Add(keyFn())
			},
		},
	})

	return c
}

// TODO(BEN): is this working?
func (c *Controller) syncConfigMap() error {
	originalAuthConfigMap, err := c.configMapLister.ConfigMaps(configMapNamespace).Get(configMapName)
	if apierrors.IsNotFound(err) {
		originalAuthConfigMap = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: configMapNamespace, Name: configMapName},
		}
	} else if err != nil {
		return err
	}

	klog.ErrorS(
		fmt.Errorf("Ben:SyncConfigMap() 🦄 🦄 🦄"),
		"what is original auth config map?",
		"original auth configmap 🦄", originalAuthConfigMap)

	// keep the original to diff against later before updating
	authConfigMap := originalAuthConfigMap.DeepCopy()

	existingAuthenticationInfo, err := getClusterAuthenticationInfoFor(originalAuthConfigMap.Data)
	if err != nil {
		return err
	}

	klog.ErrorS(
		fmt.Errorf("Ben:SyncConfigMap() 🦄 🦄 🦄 🦄"),
		"what is existing auth config map?",
		"existing auth configmap 🦄", existingAuthenticationInfo)

	combinedInfo, err := combinedClusterAuthenticationInfo(existingAuthenticationInfo, c.requiredAuthenticationData) // TODO (BEN): I could also log this....
	if err != nil {
		return err
	}

	klog.ErrorS(
		fmt.Errorf("Ben:SyncConfigMap() 🦄 🦄 🦄 🦄 🦄"),
		"what is combined info?",
		"combined 🦄", combinedInfo)

	authConfigMap.Data, err = getConfigMapDataFor(combinedInfo) // TODO: does this filter things out?
	if err != nil {
		return err
	}

	klog.ErrorS(
		fmt.Errorf("Ben:SyncConfigMap() 🦄 🦄 🦄 🦄 🦄 🦄"),
		"what is auth config map?",
		"Data 🦄", authConfigMap.Data) // TODO! HERE IT IS.... WHY DON"T WE HAVE THE DATA WE WANT??

	if equality.Semantic.DeepEqual(authConfigMap, originalAuthConfigMap) {
		klog.V(5).Info("no changes to configmap")
		return nil
	}
	klog.V(2).Infof("writing updated authentication info to  %s configmaps/%s", configMapNamespace, configMapName)

	klog.ErrorS(
		fmt.Errorf("Ben:SyncConfigMap() 🦄 🦄 🦄 🦄 🦄 🦄"),
		"writing updated authentication info to  %s configmaps/%s", configMapNamespace, configMapName,
		"", "")

	if err := createNamespaceIfNeeded(c.namespaceClient, authConfigMap.Namespace); err != nil {
		return err
	}
	if err := writeConfigMap(c.configMapClient, authConfigMap); err != nil {
		return err
	}

	return nil
}

func createNamespaceIfNeeded(nsClient corev1client.NamespacesGetter, ns string) error {
	if _, err := nsClient.Namespaces().Get(context.TODO(), ns, metav1.GetOptions{}); err == nil {
		// the namespace already exists
		return nil
	}
	newNs := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ns,
			Namespace: "",
		},
	}
	_, err := nsClient.Namespaces().Create(context.TODO(), newNs, metav1.CreateOptions{})
	if err != nil && apierrors.IsAlreadyExists(err) {
		err = nil
	}
	return err
}

func writeConfigMap(configMapClient corev1client.ConfigMapsGetter, required *corev1.ConfigMap) error {
	_, err := configMapClient.ConfigMaps(required.Namespace).Update(context.TODO(), required, metav1.UpdateOptions{})
	if apierrors.IsNotFound(err) {
		_, err := configMapClient.ConfigMaps(required.Namespace).Create(context.TODO(), required, metav1.CreateOptions{})
		return err
	}

	// If the configmap is too big, clear the entire thing and count on this controller (or another one) to add the correct data back.
	// We return the original error which causes the controller to re-queue.
	// Too big means
	//   1. request is so big the generic request catcher finds it
	//   2. the content is so large that that the server sends a validation error "Too long: must have at most 1048576 characters"
	if apierrors.IsRequestEntityTooLargeError(err) || (apierrors.IsInvalid(err) && strings.Contains(err.Error(), "Too long")) {
		if deleteErr := configMapClient.ConfigMaps(required.Namespace).Delete(context.TODO(), required.Name, metav1.DeleteOptions{}); deleteErr != nil {
			return deleteErr
		}
		return err
	}

	return err
}

// combinedClusterAuthenticationInfo combines two sets of authentication information into a new one
func combinedClusterAuthenticationInfo(lhs, rhs ClusterAuthenticationInfo) (ClusterAuthenticationInfo, error) {
	ret := ClusterAuthenticationInfo{
		RequestHeaderUsernameHeaders:     combineUniqueStringSlices(lhs.RequestHeaderUsernameHeaders, rhs.RequestHeaderUsernameHeaders),
		RequestHeaderUIDHeaders:          combineUniqueStringSlices(lhs.RequestHeaderUIDHeaders, rhs.RequestHeaderUIDHeaders),
		RequestHeaderGroupHeaders:        combineUniqueStringSlices(lhs.RequestHeaderGroupHeaders, rhs.RequestHeaderGroupHeaders),
		RequestHeaderExtraHeaderPrefixes: combineUniqueStringSlices(lhs.RequestHeaderExtraHeaderPrefixes, rhs.RequestHeaderExtraHeaderPrefixes),
		RequestHeaderAllowedNames:        combineUniqueStringSlices(lhs.RequestHeaderAllowedNames, rhs.RequestHeaderAllowedNames),
	}

	var err error
	ret.ClientCA, err = combineCertLists(lhs.ClientCA, rhs.ClientCA)
	if err != nil {
		return ClusterAuthenticationInfo{}, err
	}
	ret.RequestHeaderCA, err = combineCertLists(lhs.RequestHeaderCA, rhs.RequestHeaderCA)
	if err != nil {
		return ClusterAuthenticationInfo{}, err
	}

	return ret, nil
}

func getConfigMapDataFor(authenticationInfo ClusterAuthenticationInfo) (map[string]string, error) {
	data := map[string]string{}
	if authenticationInfo.ClientCA != nil {
		if caBytes := authenticationInfo.ClientCA.CurrentCABundleContent(); len(caBytes) > 0 {
			data["client-ca-file"] = string(caBytes)
		}
	}

	if authenticationInfo.RequestHeaderCA == nil {
		return data, nil
	}
	// TODO (BEN):
	// heh, if the CA is not set, the headers are not written.
	// the headers have no meaning without a CA to trust.
	// we need mTLS to trust the headers.
	// THEREFORE we have to check and see if hte test-cmd.sh is passing hte correct value; it wasn't :)
	if caBytes := authenticationInfo.RequestHeaderCA.CurrentCABundleContent(); len(caBytes) > 0 {
		var err error

		// encoding errors aren't going to get better, so just fail on them.
		data["requestheader-username-headers"], err = jsonSerializeStringSlice(authenticationInfo.RequestHeaderUsernameHeaders.Value())
		if err != nil {
			return nil, err
		}
		data["requestheader-uid-headers"], err = jsonSerializeStringSlice(authenticationInfo.RequestHeaderUIDHeaders.Value())
		if err != nil {
			return nil, err
		}
		data["requestheader-group-headers"], err = jsonSerializeStringSlice(authenticationInfo.RequestHeaderGroupHeaders.Value())
		if err != nil {
			return nil, err
		}
		data["requestheader-extra-headers-prefix"], err = jsonSerializeStringSlice(authenticationInfo.RequestHeaderExtraHeaderPrefixes.Value())
		if err != nil {
			return nil, err
		}

		data["requestheader-client-ca-file"] = string(caBytes)
		data["requestheader-allowed-names"], err = jsonSerializeStringSlice(authenticationInfo.RequestHeaderAllowedNames.Value())
		if err != nil {
			return nil, err
		}
	}

	return data, nil
}

func getClusterAuthenticationInfoFor(data map[string]string) (ClusterAuthenticationInfo, error) {
	ret := ClusterAuthenticationInfo{}

	var err error
	ret.RequestHeaderUsernameHeaders, err = jsonDeserializeStringSlice(data["requestheader-username-headers"])
	if err != nil {
		return ClusterAuthenticationInfo{}, err
	}
	ret.RequestHeaderUIDHeaders, err = jsonDeserializeStringSlice(data["requestheader-uid-headers"])
	if err != nil {
		return ClusterAuthenticationInfo{}, err
	}
	ret.RequestHeaderGroupHeaders, err = jsonDeserializeStringSlice(data["requestheader-group-headers"])
	if err != nil {
		return ClusterAuthenticationInfo{}, err
	}
	ret.RequestHeaderExtraHeaderPrefixes, err = jsonDeserializeStringSlice(data["requestheader-extra-headers-prefix"])
	if err != nil {
		return ClusterAuthenticationInfo{}, err
	}
	ret.RequestHeaderAllowedNames, err = jsonDeserializeStringSlice(data["requestheader-allowed-names"])
	if err != nil {
		return ClusterAuthenticationInfo{}, err
	}

	if caBundle := data["requestheader-client-ca-file"]; len(caBundle) > 0 {
		ret.RequestHeaderCA, err = dynamiccertificates.NewStaticCAContent("existing", []byte(caBundle))
		if err != nil {
			return ClusterAuthenticationInfo{}, err
		}
	}

	if caBundle := data["client-ca-file"]; len(caBundle) > 0 {
		ret.ClientCA, err = dynamiccertificates.NewStaticCAContent("existing", []byte(caBundle))
		if err != nil {
			return ClusterAuthenticationInfo{}, err
		}
	}

	return ret, nil
}

func jsonSerializeStringSlice(in []string) (string, error) {
	out, err := json.Marshal(in)
	if err != nil {
		return "", err
	}
	return string(out), err
}

func jsonDeserializeStringSlice(in string) (headerrequest.StringSliceProvider, error) {
	if len(in) == 0 {
		return nil, nil
	}

	out := []string{}
	if err := json.Unmarshal([]byte(in), &out); err != nil {
		return nil, err
	}
	return headerrequest.StaticStringSlice(out), nil
}

func combineUniqueStringSlices(lhs, rhs headerrequest.StringSliceProvider) headerrequest.StringSliceProvider {
	ret := []string{}
	present := sets.String{}

	if lhs != nil {
		for _, curr := range lhs.Value() {
			if present.Has(curr) {
				continue
			}
			ret = append(ret, curr)
			present.Insert(curr)
		}
	}

	if rhs != nil {
		for _, curr := range rhs.Value() {
			if present.Has(curr) {
				continue
			}
			ret = append(ret, curr)
			present.Insert(curr)
		}
	}

	return headerrequest.StaticStringSlice(ret)
}

func combineCertLists(lhs, rhs dynamiccertificates.CAContentProvider) (dynamiccertificates.CAContentProvider, error) {
	certificates := []*x509.Certificate{}

	if lhs != nil {
		lhsCABytes := lhs.CurrentCABundleContent()
		lhsCAs, err := cert.ParseCertsPEM(lhsCABytes)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, lhsCAs...)
	}
	if rhs != nil {
		rhsCABytes := rhs.CurrentCABundleContent()
		rhsCAs, err := cert.ParseCertsPEM(rhsCABytes)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, rhsCAs...)
	}

	certificates = filterExpiredCerts(certificates...)

	finalCertificates := []*x509.Certificate{}
	// now check for duplicates. n^2, but super simple
	for i := range certificates {
		found := false
		for j := range finalCertificates {
			if reflect.DeepEqual(certificates[i].Raw, finalCertificates[j].Raw) {
				found = true
				break
			}
		}
		if !found {
			finalCertificates = append(finalCertificates, certificates[i])
		}
	}

	finalCABytes, err := encodeCertificates(finalCertificates...)
	if err != nil {
		return nil, err
	}

	if len(finalCABytes) == 0 {
		return nil, nil
	}
	// it makes sense for this list to be static because the combination of sources is only used just before writing and
	// is recalculated
	return dynamiccertificates.NewStaticCAContent("combined", finalCABytes)
}

// filterExpiredCerts checks are all certificates in the bundle valid, i.e. they have not expired.
// The function returns new bundle with only valid certificates or error if no valid certificate is found.
// We allow five minutes of slack for NotAfter comparisons
func filterExpiredCerts(certs ...*x509.Certificate) []*x509.Certificate {
	fiveMinutesAgo := time.Now().Add(-5 * time.Minute)

	var validCerts []*x509.Certificate
	for _, c := range certs {
		if c.NotAfter.After(fiveMinutesAgo) {
			validCerts = append(validCerts, c)
		}
	}

	return validCerts
}

// Enqueue a method to allow separate control loops to cause the controller to trigger and reconcile content.
func (c *Controller) Enqueue() {
	c.queue.Add(keyFn())
}

// Run the controller until stopped.
func (c *Controller) Run(workers int, stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	// make sure the work queue is shutdown which will trigger workers to end
	defer c.queue.ShutDown()

	klog.Infof("Starting cluster_authentication_trust_controller controller")
	defer klog.Infof("Shutting down cluster_authentication_trust_controller controller")

	// we have a personal informer that is narrowly scoped, start it.
	go c.kubeSystemConfigMapInformer.Run(stopCh)

	// wait for your secondary caches to fill before starting your work
	if !cache.WaitForNamedCacheSync("cluster_authentication_trust_controller", stopCh, c.preRunCaches...) {
		return
	}

	// only run one worker
	go wait.Until(c.runWorker, time.Second, stopCh)

	// checks are cheap.  run once a minute just to be sure we stay in sync in case fsnotify fails again
	// start timer that rechecks every minute, just in case.  this also serves to prime the controller quickly.
	_ = wait.PollImmediateUntil(1*time.Minute, func() (bool, error) {
		c.queue.Add(keyFn())
		return false, nil
	}, stopCh)

	// wait until we're told to stop
	<-stopCh
}

func (c *Controller) runWorker() {
	// hot loop until we're told to stop.  processNextWorkItem will automatically wait until there's work
	// available, so we don't worry about secondary waits
	for c.processNextWorkItem() {
	}
}

// processNextWorkItem deals with one key off the queue.  It returns false when it's time to quit.
func (c *Controller) processNextWorkItem() bool {
	// pull the next work item from queue.  It should be a key we use to lookup something in a cache
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	// you always have to indicate to the queue that you've completed a piece of work
	defer c.queue.Done(key)

	// TODO: BEN..... tracking.
	// do your work on the key.  This method will contains your "do stuff" logic
	err := c.syncConfigMap()
	if err == nil {
		// if you had no error, tell the queue to stop tracking history for your key.  This will
		// reset things like failure counts for per-item rate limiting
		c.queue.Forget(key)
		return true
	}

	// there was a failure so be sure to report it.  This method allows for pluggable error handling
	// which can be used for things like cluster-monitoring
	utilruntime.HandleError(fmt.Errorf("%v failed with : %v", key, err))
	// since we failed, we should requeue the item to work on later.  This method will add a backoff
	// to avoid hotlooping on particular items (they're probably still not going to work right away)
	// and overall controller protection (everything I've done is broken, this controller needs to
	// calm down or it can starve other useful work) cases.
	c.queue.AddRateLimited(key)

	return true
}

func keyFn() string {
	// this format matches DeletionHandlingMetaNamespaceKeyFunc for our single key
	return configMapNamespace + "/" + configMapName
}

func encodeCertificates(certs ...*x509.Certificate) ([]byte, error) {
	b := bytes.Buffer{}
	for _, cert := range certs {
		if err := pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return []byte{}, err
		}
	}
	return b.Bytes(), nil
}
