package goprotofuzz_test

import (
	"testing"

	gofuzz "github.com/google/gofuzz"
	"github.com/srikrsna/goprotofuzz"
	testv1 "github.com/srikrsna/goprotofuzz/internal/gen/test/v1"
	"github.com/srikrsna/goprotofuzz/internal/gen/test/v1/testv1fuzz"
	"google.golang.org/protobuf/proto"
)

func FuzzFuzz(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		f := gofuzz.NewFromGoFuzz(data).Funcs(testv1fuzz.FuzzFuncs()...).Funcs(goprotofuzz.FuzzWKT[:]...)
		var all testv1.All
		f.Fuzz(&all)
		if !all.ProtoReflect().IsValid() {
			t.Error("invalid proto")
		}
		if _, err := proto.Marshal(&all); err != nil {
			t.Error("failed to marshal")
		}
	})
}
