package context

import (
	"encoding/json"
	"testing"

	urkyverno "github.com/kyverno/kyverno/api/kyverno/v1beta1"
	"github.com/kyverno/kyverno/pkg/config"
	"github.com/kyverno/kyverno/pkg/engine/jmespath"
	"gotest.tools/assert"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var jp = jmespath.New(config.NewDefaultConfiguration(false))

func newTestResource() []byte {
	return []byte(`
	{
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
		   "name": "image-with-hostpath",
		   "labels": {
			  "app.type": "prod",
			  "namespace": "my-namespace"
		   }
		},
		"spec": {
		   "containers": [
			  {
				 "name": "image_with_hostpath",
				 "image": "docker.io/nautiker/curl",
				 "volumeMounts": [
					{
					   "name": "var-lib-etcd",
					   "mountPath": "/var/lib"
					}
				 ]
			  }
		   ],
		   "volumes": [
			  {
				 "name": "var-lib-etcd",
				 "emptyDir": {}
			  }
		   ]
		}
	 }
	`)
}

func TestAddResourceAndUserContext(t *testing.T) {
	var err error
	rawResource := newTestResource()
	userInfo := authenticationv1.UserInfo{
		Username: "system:serviceaccount:nirmata:user1",
		UID:      "014fbff9a07c",
	}
	userRequestInfo := urkyverno.RequestInfo{
		Roles:             nil,
		ClusterRoles:      nil,
		AdmissionUserInfo: userInfo,
	}

	ctx := NewContext(jp)
	err = AddResource(ctx, rawResource)
	assert.NilError(t, err)

	result, err := ctx.Query("request.object.apiVersion")
	assert.NilError(t, err)
	assert.Equal(t, "v1", result)

	err = ctx.AddUserInfo(userRequestInfo)
	assert.NilError(t, err)

	result, err = ctx.Query("request.object.apiVersion")
	assert.NilError(t, err)
	assert.Equal(t, "v1", result)

	result, err = ctx.Query("request.userInfo.username")
	assert.NilError(t, err)
	assert.Equal(t, "system:serviceaccount:nirmata:user1", result)

	// Add service account Name
	err = ctx.AddServiceAccount(userRequestInfo.AdmissionUserInfo.Username)
	assert.NilError(t, err)

	result, err = ctx.Query("serviceAccountName")
	assert.NilError(t, err)
	assert.Equal(t, "user1", result)

	result, err = ctx.Query("serviceAccountNamespace")
	assert.NilError(t, err)
	assert.Equal(t, "nirmata", result)

	err = ctx.ReplaceContextEntry("request", []byte(`{}`))
	assert.NilError(t, err)
	_, err = ctx.Query("request.object")
	assert.ErrorContains(t, err, "Unknown key \"object\" in path")
}

func TestParseImageInfo(t *testing.T) {
	rawJson := map[string]interface{}{}
	err := json.Unmarshal(newTestResource(), &rawJson)
	assert.NilError(t, err)

	resource := &unstructured.Unstructured{
		Object: rawJson,
	}

	ctx := NewContext(jp)
	err = ctx.AddImageInfos(resource, config.NewDefaultConfiguration(false))
	assert.NilError(t, err)

	imageInfo := ctx.ImageInfo()
	assert.Equal(t, "docker.io", imageInfo["containers"]["image_with_hostpath"].Registry)
	assert.Equal(t, "nautiker/curl", imageInfo["containers"]["image_with_hostpath"].Path)
	assert.Equal(t, "curl", imageInfo["containers"]["image_with_hostpath"].Name)

	result, err := ctx.Query("images.containers.image_with_hostpath")
	assert.NilError(t, err)

	rawImageInfo, ok := result.(map[string]interface{})
	assert.Assert(t, ok)
	assert.Equal(t, "docker.io", rawImageInfo["registry"])
	assert.Equal(t, "nautiker/curl", rawImageInfo["path"])
	assert.Equal(t, "curl", rawImageInfo["name"])
}
