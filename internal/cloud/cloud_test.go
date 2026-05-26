package cloud

import "testing"

func TestDetectScheme(t *testing.T) {
	cases := []struct {
		in   string
		want Scheme
	}{
		{"az://container/blob", SchemeAzure},
		{"s3://bucket/key", SchemeS3},
		{"gs://bucket/key", SchemeGCS},
		{"https://example.com/bundle.vpack", SchemeHTTPS},
		{"http://example.com/bundle.vpack", SchemeHTTP},
		{"./relative/path", SchemeLocal},
		{"C:\\Users\\foo\\file.vpack", SchemeLocal},
		{"/absolute/path", SchemeLocal},
		{"", SchemeLocal},
	}
	for _, c := range cases {
		got := DetectScheme(c.in)
		if got != c.want {
			t.Errorf("DetectScheme(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsRemote(t *testing.T) {
	if !IsRemote("az://x/y") {
		t.Error("az:// should be remote")
	}
	if !IsRemote("s3://b/k") {
		t.Error("s3:// should be remote")
	}
	if !IsRemote("gs://b/k") {
		t.Error("gs:// should be remote")
	}
	if !IsRemote("https://x/y") {
		t.Error("https:// should be remote")
	}
	if IsRemote("./local") {
		t.Error("local path should not be remote")
	}
}

func TestIsWritable(t *testing.T) {
	if !IsWritable("az://x/y") {
		t.Error("az:// should be writable")
	}
	if !IsWritable("s3://b/k") {
		t.Error("s3:// should be writable")
	}
	if !IsWritable("gs://b/k") {
		t.Error("gs:// should be writable")
	}
	if IsWritable("https://x/y") {
		t.Error("https:// should not be writable")
	}
	if IsWritable("http://x/y") {
		t.Error("http:// should not be writable")
	}
	if !IsWritable("./local") {
		t.Error("local should be writable")
	}
}

func TestParseBucketKey(t *testing.T) {
	cases := []struct {
		uri        string
		wantBucket string
		wantKey    string
		wantErr    bool
	}{
		{"s3://bucket/key/path", "bucket", "key/path", false},
		{"gs://my-bucket/a/b/c.vpack", "my-bucket", "a/b/c.vpack", false},
		{"s3://bucket", "bucket", "", false},
		{"s3://bucket/", "bucket", "", false},
		{"s3://", "", "", true},
		{"not-a-uri", "", "", true},
	}
	for _, c := range cases {
		b, k, err := ParseBucketKey(c.uri)
		if (err != nil) != c.wantErr {
			t.Errorf("ParseBucketKey(%q) err=%v wantErr=%v", c.uri, err, c.wantErr)
			continue
		}
		if err != nil {
			continue
		}
		if b != c.wantBucket || k != c.wantKey {
			t.Errorf("ParseBucketKey(%q) = (%q, %q), want (%q, %q)", c.uri, b, k, c.wantBucket, c.wantKey)
		}
	}
}
