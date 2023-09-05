package jsonutils

import jsoniter "github.com/json-iterator/go"

// DocumentToUntyped converts a typed object to JSON data
// i.e. string, []interface{}, map[string]interface{}
func DocumentToUntyped(doc interface{}) (interface{}, error) {
	var json = jsoniter.ConfigCompatibleWithStandardLibrary
	jsonDoc, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}

	var untyped interface{}
	err = json.Unmarshal(jsonDoc, &untyped)
	if err != nil {
		return nil, err
	}

	return untyped, nil
}
