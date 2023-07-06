package goprotofuzz

import (
	"strings"
	"time"

	fuzz "github.com/google/gofuzz"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var FuzzWKT = [...]interface{}{FuzzAny, FuzzDuration, FuzzStruct, FuzzTimestamp, FuzzFieldMask, FuzzValue}

// FuzzAny can be used to Fuzz google.protobuf.Any messages.
// It fills a fuzzed google.protobuf.Struct message.
func FuzzAny(msg *anypb.Any, c fuzz.Continue) {
	var st structpb.Struct
	c.Fuzz(&st)
	msg.MarshalFrom(&st)
}

// FuzzStruct can be used to Fuzz google.protobuf.Struct messages.
// # of fields will be in [0, 64). Each field will be one of float, bool, or string
func FuzzStruct(msg *structpb.Struct, c fuzz.Continue) {
	fc := c.Rand.Intn(21)
	msg.Fields = make(map[string]*structpb.Value, fc)
	for i := 0; i < fc; i++ {
		var v *structpb.Value
		switch c.Int() % 3 {
		case 0:
			v = structpb.NewNumberValue(c.Float64())
		case 1:
			v = structpb.NewBoolValue(c.RandBool())
		case 2:
			v = structpb.NewStringValue(c.RandString())
		}
		msg.Fields[c.RandString()] = v
	}
}

// FuzzStruct can be used to Fuzz google.protobuf.Value messages.
// Values can be null, string, number, bool or struct
func FuzzValue(msg *structpb.Value, c fuzz.Continue) {
	switch c.Int() % 5 {
	case 0:
		msg.Kind = structpb.NewNullValue().Kind
	case 1:
		msg.Kind = structpb.NewStringValue(c.RandString()).Kind
	case 2:
		msg.Kind = structpb.NewBoolValue(c.RandBool()).Kind
	case 3:
		msg.Kind = structpb.NewNumberValue(c.NormFloat64()).Kind
	case 4:
		var structValue structpb.Struct
		c.Fuzz(&structValue)
		msg.Kind = structpb.NewStructValue(&structValue).Kind
	}
}

// FuzzTimestamp can be used to Fuzz google.protobuf.Timestamp messages.
// It's range is same as default time.Time fuzzer of gofuzz
func FuzzTimestamp(msg *timestamppb.Timestamp, c fuzz.Continue) {
	var t time.Time
	c.Fuzz(&t)
	*msg = *timestamppb.New(t)
}

// FuzzDuration can be used to Fuzz google.protobuf.Duration messages.
// It's range is [0, 1 year)
func FuzzDuration(msg *durationpb.Duration, c fuzz.Continue) {
	msg.Seconds = c.Int63n(365 * 24 * 60 * 60)
}

var (
	fieldNameFuzzFn = fuzz.UnicodeRanges{
		{
			First: rune('a'),
			Last:  rune('z'),
		},
	}.CustomStringFuzzFunc()
)

// FuzzFieldMask can be used to Fuzz google.protobuf.FieldMask messages.
// They produce valid lower_snake_case paths
func FuzzFieldMask(msg *fieldmaskpb.FieldMask, c fuzz.Continue) {
	c.Fuzz(&msg.Paths)
	for i := range msg.Paths {
		words := make([]string, 1+c.Intn(2))
		switch len(words) {
		case 2:
			for words[1] == "" {
				fieldNameFuzzFn(&words[1], c)
			}
			fallthrough
		case 1:
			for words[0] == "" {
				fieldNameFuzzFn(&words[0], c)
			}
		}
		msg.Paths[i] = strings.Join(words, "_")
	}
}
