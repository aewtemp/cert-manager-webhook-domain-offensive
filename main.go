package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(GroupName,
		&domainOffensiveDNSProviderSolver{},
	)
}

type domainOffensiveDNSProviderSolver struct {
	client *kubernetes.Clientset
}

type domainOffensiveDNSProviderConfig struct {
	ApiURL string `json:"apiUrl"`
	SecretKeyRef corev1.SecretKeySelector `json:"secretKeyRef"`
}

func (c *domainOffensiveDNSProviderSolver) Name() string {
	return "domain-offensive"
}

func (c *domainOffensiveDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	klog.Infof("call function Present: namespace=%s, zone=%s, fqdn=%s",
		ch.ResourceNamespace, ch.ResolvedZone, ch.ResolvedFQDN)

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	if cfg.SecretKeyRef.Key == "" { return errors.New("missing SecretKeyRef") }
	sec, err := c.client.CoreV1().Secrets(ch.ResourceNamespace).Get(context.TODO(), cfg.SecretKeyRef.Name, v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to get secret `%s/%s`; %v", ch.ResourceNamespace, cfg.SecretKeyRef.Name, err)
	}

	token, err := stringFromSecretData(sec.Data, "token")
	if err != nil {
		return err
	}

	if err := presentRecord(ch, cfg.ApiURL, token); err != nil {
		return err
	}

	return nil
}

func (c *domainOffensiveDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	klog.Infof("call function CleanUp: namespace=%s, zone=%s, fqdn=%s",
		ch.ResourceNamespace, ch.ResolvedZone, ch.ResolvedFQDN)

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	if cfg.SecretKeyRef.Key == "" { return errors.New("missing SecretKeyRef") }
	sec, err := c.client.CoreV1().Secrets(ch.ResourceNamespace).Get(context.TODO(), cfg.SecretKeyRef.Name, v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to get secret `%s/%s`; %v", ch.ResourceNamespace, cfg.SecretKeyRef.Name, err)
	}

	token, err := stringFromSecretData(sec.Data, "token")
	if err != nil {
		return err
	}

	if err := deleteRecord(ch, cfg.ApiURL, token); err != nil {
		return err
	}

	return nil
}

func (c *domainOffensiveDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {

	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}
	c.client = cl

	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (domainOffensiveDNSProviderConfig, error) {
	cfg := domainOffensiveDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}

	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	if cfg.ApiURL == "" {
		cfg.ApiURL = "https://my.do.de/api/letsencrypt"
	}

	klog.InfoS("Solver configuration loaded",
		"apiUrl", cfg.ApiURL,
		"secretKeyRef", cfg.SecretKeyRef,
	)

	return cfg, nil
}

func stringFromSecretData(secretData map[string][]byte, key string) (string, error) {
	data, ok := secretData[key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret data", key)
	}
	return string(data), nil
}

func presentRecord(ch *v1alpha1.ChallengeRequest, apiUrl, token string) error {
    return callDoApi(ch, apiUrl, token, false)
}

func deleteRecord(ch *v1alpha1.ChallengeRequest, apiUrl, token string) error {
    return callDoApi(ch, apiUrl, token, true)
}

func callDoApi(ch *v1alpha1.ChallengeRequest, apiUrl string, token string, delete bool) (error) {
	fqdn := ch.ResolvedFQDN
	fqdn = strings.TrimSuffix(fqdn, ".")
	val := ch.Key

	q := url.Values{}
	q.Set("token", token)
	q.Set("domain", fqdn)
	q.Set("value", val)
	if delete { q.Set("action", "delete") }
	uri := apiUrl + "?" + q.Encode()

	resp, err := http.Get(uri) // #nosec G107
	if err != nil {
		return fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %w", err)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("api status %d: %s", resp.StatusCode, string(body))
	}

	var jr struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(body, &jr); err != nil {
		return fmt.Errorf("error decoding api response: %w (body=%s)", err, string(body))
	}
	if !jr.Success {
		return fmt.Errorf("api returned success=false: %s", string(body))
	}

	if !delete {
		klog.Infof("Presented acme txt record %v", ch.ResolvedFQDN)
	} else {
		klog.Infof("Cleaned up acme txt record %v", ch.ResolvedFQDN)
	}

	return nil
}
