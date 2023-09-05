package context

import (
	"encoding/json"
	"reflect"

	"k8s.io/apimachinery/pkg/runtime"
)

// AddJSONObject merges json data
func AddJSONObject(ctx Interface, data map[string]interface{}) error {
	return ctx.addJSON(data)
}

func AddResource(ctx Interface, dataRaw []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(dataRaw, &data); err != nil {
		logger.Error(err, "failed to unmarshal the resource")
		return err
	}
	return ctx.AddResource(data)
}

func AddOldResource(ctx Interface, dataRaw []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(dataRaw, &data); err != nil {
		logger.Error(err, "failed to unmarshal the resource")
		return err
	}
	return ctx.AddOldResource(data)
}

func addToContext(ctx *context, value interface{}, tags ...string) error {
	if v, err := convertStructs(value); err == nil {
		dataRaw := push(v, tags...)
		return ctx.addJSON(dataRaw)
	} else {
		return err
	}
}

// convertStructs converts strucs and pointers to structs to a map[string]interface{}
func convertStructs(value interface{}) (interface{}, error) {
	if value != nil {
		v := reflect.ValueOf(value)
		if v.Kind() == reflect.Struct {
			return toUnstructured(value)
		}

		if v.Kind() == reflect.Ptr {
			ptrVal := v.Elem()
			if ptrVal.Kind() == reflect.Struct {
				return toUnstructured(value)
			}
		}
	}

	return value, nil
}

func push(data interface{}, tags ...string) map[string]interface{} {
	for i := len(tags) - 1; i >= 0; i-- {
		data = map[string]interface{}{
			tags[i]: data,
		}
	}

	return data.(map[string]interface{})
}

// mergeMaps merges srcMap entries into destMap
func mergeMaps(srcMap, destMap map[string]interface{}) {
	for k, v := range srcMap {
		if nextSrcMap, ok := v.(map[string]interface{}); ok {
			if nextDestMap, ok := destMap[k].(map[string]interface{}); ok {
				mergeMaps(nextSrcMap, nextDestMap)
			} else {
				destMap[k] = nextSrcMap
			}
		} else {
			destMap[k] = v
		}
	}
}

// toUnstructured converts a struct with JSON tags to a map[string]interface{}
func toUnstructured(typedStruct interface{}) (map[string]interface{}, error) {
	converter := runtime.DefaultUnstructuredConverter
	u, err := converter.ToUnstructured(typedStruct)
	return u, err
}
