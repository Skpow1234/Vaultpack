package bundle

import (
	"encoding/json"
	"fmt"
	"sort"
)

// MarshalManifest serializes a Manifest to indented JSON.
func MarshalManifest(m *Manifest) ([]byte, error) {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	return append(data, '\n'), nil
}

// UnmarshalManifest deserializes JSON bytes into a Manifest.
func UnmarshalManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("unmarshal manifest: %w", err)
	}
	return &m, nil
}

// CanonicalManifest returns deterministic JSON bytes for signing.
// Keys are sorted and no extra whitespace is added.
func CanonicalManifest(m *Manifest) ([]byte, error) {
	// Marshal to generic map, then re-encode with sorted keys.
	data, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("canonical marshal step 1: %w", err)
	}

	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		return nil, fmt.Errorf("canonical marshal step 2: %w", err)
	}

	canonical, err := marshalSorted(generic)
	if err != nil {
		return nil, fmt.Errorf("canonical marshal step 3: %w", err)
	}
	return canonical, nil
}

// marshalSorted recursively marshals a map with sorted keys.
func marshalSorted(v any) ([]byte, error) {
	switch val := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		buf := []byte("{")
		for i, k := range keys {
			if i > 0 {
				buf = append(buf, ',')
			}
			keyBytes, _ := json.Marshal(k)
			buf = append(buf, keyBytes...)
			buf = append(buf, ':')
			valBytes, err := marshalSorted(val[k])
			if err != nil {
				return nil, err
			}
			buf = append(buf, valBytes...)
		}
		buf = append(buf, '}')
		return buf, nil
	case []any:
		buf := []byte("[")
		for i, item := range val {
			if i > 0 {
				buf = append(buf, ',')
			}
			itemBytes, err := marshalSorted(item)
			if err != nil {
				return nil, err
			}
			buf = append(buf, itemBytes...)
		}
		buf = append(buf, ']')
		return buf, nil
	default:
		return json.Marshal(v)
	}
}
