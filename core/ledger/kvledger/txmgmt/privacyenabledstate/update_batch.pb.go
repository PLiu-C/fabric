// Code generated by protoc-gen-go. DO NOT EDIT.
// source: update_batch.proto

package privacyenabledstate // import "github.com/hyperledger/fabric/core/ledger/kvledger/txmgmt/privacyenabledstate"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type KVWriteProto struct {
	Namespace            string   `protobuf:"bytes,1,opt,name=namespace,proto3" json:"namespace,omitempty"`
	Collection           string   `protobuf:"bytes,2,opt,name=collection,proto3" json:"collection,omitempty"`
	Key                  []byte   `protobuf:"bytes,3,opt,name=key,proto3" json:"key,omitempty"`
	IsDelete             bool     `protobuf:"varint,4,opt,name=isDelete,proto3" json:"isDelete,omitempty"`
	Value                []byte   `protobuf:"bytes,5,opt,name=value,proto3" json:"value,omitempty"`
	VersionBytes         []byte   `protobuf:"bytes,6,opt,name=version_bytes,json=versionBytes,proto3" json:"version_bytes,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *KVWriteProto) Reset()         { *m = KVWriteProto{} }
func (m *KVWriteProto) String() string { return proto.CompactTextString(m) }
func (*KVWriteProto) ProtoMessage()    {}
func (*KVWriteProto) Descriptor() ([]byte, []int) {
	return fileDescriptor_update_batch_169d334cdaab572b, []int{0}
}
func (m *KVWriteProto) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_KVWriteProto.Unmarshal(m, b)
}
func (m *KVWriteProto) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_KVWriteProto.Marshal(b, m, deterministic)
}
func (dst *KVWriteProto) XXX_Merge(src proto.Message) {
	xxx_messageInfo_KVWriteProto.Merge(dst, src)
}
func (m *KVWriteProto) XXX_Size() int {
	return xxx_messageInfo_KVWriteProto.Size(m)
}
func (m *KVWriteProto) XXX_DiscardUnknown() {
	xxx_messageInfo_KVWriteProto.DiscardUnknown(m)
}

var xxx_messageInfo_KVWriteProto proto.InternalMessageInfo

func (m *KVWriteProto) GetNamespace() string {
	if m != nil {
		return m.Namespace
	}
	return ""
}

func (m *KVWriteProto) GetCollection() string {
	if m != nil {
		return m.Collection
	}
	return ""
}

func (m *KVWriteProto) GetKey() []byte {
	if m != nil {
		return m.Key
	}
	return nil
}

func (m *KVWriteProto) GetIsDelete() bool {
	if m != nil {
		return m.IsDelete
	}
	return false
}

func (m *KVWriteProto) GetValue() []byte {
	if m != nil {
		return m.Value
	}
	return nil
}

func (m *KVWriteProto) GetVersionBytes() []byte {
	if m != nil {
		return m.VersionBytes
	}
	return nil
}

type KVWritesBatchProto struct {
	Kvwrites             []*KVWriteProto `protobuf:"bytes,1,rep,name=kvwrites,proto3" json:"kvwrites,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *KVWritesBatchProto) Reset()         { *m = KVWritesBatchProto{} }
func (m *KVWritesBatchProto) String() string { return proto.CompactTextString(m) }
func (*KVWritesBatchProto) ProtoMessage()    {}
func (*KVWritesBatchProto) Descriptor() ([]byte, []int) {
	return fileDescriptor_update_batch_169d334cdaab572b, []int{1}
}
func (m *KVWritesBatchProto) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_KVWritesBatchProto.Unmarshal(m, b)
}
func (m *KVWritesBatchProto) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_KVWritesBatchProto.Marshal(b, m, deterministic)
}
func (dst *KVWritesBatchProto) XXX_Merge(src proto.Message) {
	xxx_messageInfo_KVWritesBatchProto.Merge(dst, src)
}
func (m *KVWritesBatchProto) XXX_Size() int {
	return xxx_messageInfo_KVWritesBatchProto.Size(m)
}
func (m *KVWritesBatchProto) XXX_DiscardUnknown() {
	xxx_messageInfo_KVWritesBatchProto.DiscardUnknown(m)
}

var xxx_messageInfo_KVWritesBatchProto proto.InternalMessageInfo

func (m *KVWritesBatchProto) GetKvwrites() []*KVWriteProto {
	if m != nil {
		return m.Kvwrites
	}
	return nil
}

func init() {
	proto.RegisterType((*KVWriteProto)(nil), "privacyenabledstate.KVWriteProto")
	proto.RegisterType((*KVWritesBatchProto)(nil), "privacyenabledstate.KVWritesBatchProto")
}

func init() { proto.RegisterFile("update_batch.proto", fileDescriptor_update_batch_169d334cdaab572b) }

var fileDescriptor_update_batch_169d334cdaab572b = []byte{
	// 281 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x90, 0xc1, 0x4b, 0xc3, 0x30,
	0x14, 0xc6, 0x89, 0x73, 0x63, 0x8b, 0x13, 0x24, 0x7a, 0x08, 0x22, 0x52, 0xe7, 0xa5, 0xa7, 0x16,
	0xf4, 0xec, 0x65, 0x78, 0x13, 0x51, 0x2a, 0x28, 0x78, 0x19, 0x49, 0xf6, 0x5c, 0x43, 0xd3, 0xa6,
	0x24, 0xaf, 0xd5, 0xfe, 0x61, 0xfe, 0x7f, 0xd2, 0xac, 0xcc, 0x1d, 0x76, 0x7b, 0xef, 0xf7, 0x7d,
	0x21, 0xdf, 0xf7, 0x28, 0x6b, 0xea, 0xb5, 0x40, 0x58, 0x49, 0x81, 0x2a, 0x4f, 0x6a, 0x67, 0xd1,
	0xb2, 0xf3, 0xda, 0xe9, 0x56, 0xa8, 0x0e, 0x2a, 0x21, 0x0d, 0xac, 0x3d, 0x0a, 0x84, 0xc5, 0x2f,
	0xa1, 0xf3, 0xa7, 0xf7, 0x0f, 0xa7, 0x11, 0x5e, 0x83, 0xeb, 0x8a, 0xce, 0x2a, 0x51, 0x82, 0xaf,
	0x85, 0x02, 0x4e, 0x22, 0x12, 0xcf, 0xb2, 0x7f, 0xc0, 0xae, 0x29, 0x55, 0xd6, 0x18, 0x50, 0xa8,
	0x6d, 0xc5, 0x8f, 0x82, 0xbc, 0x47, 0xd8, 0x19, 0x1d, 0x15, 0xd0, 0xf1, 0x51, 0x44, 0xe2, 0x79,
	0xd6, 0x8f, 0xec, 0x92, 0x4e, 0xb5, 0x7f, 0x04, 0x03, 0x08, 0xfc, 0x38, 0x22, 0xf1, 0x34, 0xdb,
	0xed, 0xec, 0x82, 0x8e, 0x5b, 0x61, 0x1a, 0xe0, 0xe3, 0xe0, 0xdf, 0x2e, 0xec, 0x96, 0x9e, 0xb6,
	0xe0, 0xbc, 0xb6, 0xd5, 0x4a, 0x76, 0x08, 0x9e, 0x4f, 0x82, 0x3a, 0x1f, 0xe0, 0xb2, 0x67, 0x8b,
	0x37, 0xca, 0x86, 0xd8, 0x7e, 0xd9, 0x77, 0xdc, 0x86, 0x7f, 0xa0, 0xd3, 0xa2, 0xfd, 0x0e, 0x94,
	0x93, 0x68, 0x14, 0x9f, 0xdc, 0xdd, 0x24, 0x07, 0x5a, 0x27, 0xfb, 0x8d, 0xb3, 0xdd, 0x93, 0xe5,
	0xcb, 0xe7, 0xf3, 0x46, 0x63, 0xde, 0xc8, 0x44, 0xd9, 0x32, 0xcd, 0xbb, 0x1a, 0x9c, 0x81, 0xf5,
	0x06, 0x5c, 0xfa, 0x25, 0xa4, 0xd3, 0x2a, 0x55, 0xd6, 0x41, 0x3a, 0xa0, 0xa2, 0x1d, 0x06, 0xfc,
	0x29, 0x37, 0x25, 0xa6, 0x07, 0xfe, 0x91, 0x93, 0x70, 0xf9, 0xfb, 0xbf, 0x00, 0x00, 0x00, 0xff,
	0xff, 0xcc, 0xa1, 0x09, 0xeb, 0x8f, 0x01, 0x00, 0x00,
}
