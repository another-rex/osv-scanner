package packageenricher

// BinaryPackage records data read from a binary package (a .deb file).
type BinaryPackage struct {
	//Key      *exokey.AptBinaryPackage `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	//Metadata *BinaryPackage_Metadata  `protobuf:"bytes,2,opt,name=metadata,proto3" json:"metadata,omitempty"`
	// Structured data read directly from the .deb file.
	Data *BinaryPackageData `protobuf:"bytes,3,opt,name=data,proto3" json:"data,omitempty"`
}

// BinaryPackageData holds data read from a binary package (a .deb file).
// https://manpages.debian.org/bookworm/dpkg-dev/deb.5.en.html
type BinaryPackageData struct {

	// The contents of the debian-binary file. Expected to be "2.0\n".
	DebianBinary []byte                     `protobuf:"bytes,1,opt,name=debian_binary,json=debianBinary,proto3" json:"debian_binary,omitempty"`
	Control      *BinaryPackageData_Control `protobuf:"bytes,2,opt,name=control,proto3" json:"control,omitempty"`
	//Data         *BinaryPackageData_Data    `protobuf:"bytes,3,opt,name=data,proto3" json:"data,omitempty"`
}

type BinaryPackageData_Control struct {
	// The filename of the control archive.
	// Example: control.tar.gz
	Filename string `protobuf:"bytes,1,opt,name=filename,proto3" json:"filename,omitempty"`
	// The parsed contents of the control file in the control archive.
	Control *BinaryPackageStanza `protobuf:"bytes,2,opt,name=control,proto3" json:"control,omitempty"`
}

// BinaryPackageStanza holds data parsed from a binary package stanza, whether
// in an index or a control file.
//
// The names and order of the fields are taken from the Debian Policy Manual
// and Debian Wiki:
// https://www.debian.org/doc/debian-policy/ch-controlfields.html#debian-binary-package-control-files-debian-control
// https://wiki.debian.org/DebianRepository/Format#A.22Packages.22_Indices
type BinaryPackageStanza struct {

	// The name of the package.
	// https://www.debian.org/doc/debian-policy/ch-controlfields.html#package
	Package string `json:"package,omitempty"`
	// The source package that the binary package was built from. Source and
	// binary packages exist in separate namespaces.
	// https://www.debian.org/doc/debian-policy/ch-controlfields.html#source
	Source *Source `json:"source,omitempty"`
	//// The version of the package. Typically an upstream version extended with
	//// additional information by the distributor (e.g. Debian).
	//// https://www.debian.org/doc/debian-policy/ch-controlfields.html#version
	//Version  string `protobuf:"bytes,3,opt,name=version,proto3" json:"version,omitempty"`
	//Section  string `protobuf:"bytes,4,opt,name=section,proto3" json:"section,omitempty"`
	//Priority string `protobuf:"bytes,5,opt,name=priority,proto3" json:"priority,omitempty"`
	//// The machine architecture this package was built for, or the special value
	//// "all" for an architecture-independent package.
	//// https://www.debian.org/doc/debian-policy/ch-controlfields.html#architecture
	//Architecture string `protobuf:"bytes,6,opt,name=architecture,proto3" json:"architecture,omitempty"`
	//Essential    bool   `protobuf:"varint,7,opt,name=essential,proto3" json:"essential,omitempty"`
	//// These fields hold data on how this package depends on or otherwise
	//// interacts with other packages.
	//// https://www.debian.org/doc/debian-policy/ch-relationships.html
	//Depends       []*DependencyGroup `protobuf:"bytes,8,rep,name=depends,proto3" json:"depends,omitempty"`
	//PreDepends    []*DependencyGroup `protobuf:"bytes,9,rep,name=pre_depends,json=preDepends,proto3" json:"pre_depends,omitempty"`
	//Recommends    []*DependencyGroup `protobuf:"bytes,10,rep,name=recommends,proto3" json:"recommends,omitempty"`
	//Suggests      []*DependencyGroup `protobuf:"bytes,11,rep,name=suggests,proto3" json:"suggests,omitempty"`
	//Breaks        []*DependencyGroup `protobuf:"bytes,12,rep,name=breaks,proto3" json:"breaks,omitempty"`
	//Conflicts     []*DependencyGroup `protobuf:"bytes,13,rep,name=conflicts,proto3" json:"conflicts,omitempty"`
	//Provides      []*DependencyGroup `protobuf:"bytes,14,rep,name=provides,proto3" json:"provides,omitempty"`
	//Replaces      []*DependencyGroup `protobuf:"bytes,15,rep,name=replaces,proto3" json:"replaces,omitempty"`
	//Enhances      []*DependencyGroup `protobuf:"bytes,16,rep,name=enhances,proto3" json:"enhances,omitempty"`
	//InstalledSize uint64             `protobuf:"varint,17,opt,name=installed_size,json=installedSize,proto3" json:"installed_size,omitempty"`
	//Maintainer    string             `protobuf:"bytes,18,opt,name=maintainer,proto3" json:"maintainer,omitempty"`
	//// A human-readable description of the package, in the form of a single-line
	//// synopsis followed by an extended description. In a package index, only the
	//// synopsis is retained.
	//// https://www.debian.org/doc/debian-policy/ch-controlfields.html#description
	//Description string `protobuf:"bytes,19,opt,name=description,proto3" json:"description,omitempty"`
	//Homepage    string `protobuf:"bytes,20,opt,name=homepage,proto3" json:"homepage,omitempty"`
	//// Additional source packages used to build the binary package. Note that
	//// actual usage of this field appears to be inconsistent.
	//// https://www.debian.org/doc/debian-policy/ch-relationships.html#additional-source-packages-used-to-build-the-binary-built-using
	//BuiltUsing []*DependencyGroup `protobuf:"bytes,21,rep,name=built_using,json=builtUsing,proto3" json:"built_using,omitempty"`
	//// The filename of the binary package archive (the .deb file), relative to
	//// the repository base URL.
	//// https://wiki.debian.org/DebianRepository/Format#Filename
	//Filename         string   `protobuf:"bytes,22,opt,name=filename,proto3" json:"filename,omitempty"`
	//Size             uint64   `protobuf:"varint,23,opt,name=size,proto3" json:"size,omitempty"`
	//Md5Sum           []byte   `protobuf:"bytes,24,opt,name=md5sum,proto3" json:"md5sum,omitempty"`
	//Sha1             []byte   `protobuf:"bytes,25,opt,name=sha1,proto3" json:"sha1,omitempty"`
	//Sha256           []byte   `protobuf:"bytes,26,opt,name=sha256,proto3" json:"sha256,omitempty"`
	//DescriptionMd5   []byte   `protobuf:"bytes,27,opt,name=description_md5,json=descriptionMd5,proto3" json:"description_md5,omitempty"`
	//MultiArch        string   `protobuf:"bytes,28,opt,name=multi_arch,json=multiArch,proto3" json:"multi_arch,omitempty"`
	//AdditionalFields []*Field `protobuf:"bytes,99,rep,name=additional_fields,json=additionalFields,proto3" json:"additional_fields,omitempty"`
}

// Source identifies a source package
type Source struct {
	// The name of the source package.
	Package string `json:"package,omitempty"`
	// The version of the source package, if specified, otherwise not set.
	Version string `json:"version,omitempty"`
}
