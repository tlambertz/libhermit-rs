(function() {var implementors = {};
implementors["hermit"] = [{"text":"impl&lt;'a&gt; !Freeze for SpinlockContainer&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; !Freeze for SpinlockIrqSaveContainer&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Freeze for itimerval","synthetic":true,"types":[]},{"text":"impl Freeze for timespec","synthetic":true,"types":[]},{"text":"impl Freeze for timeval","synthetic":true,"types":[]},{"text":"impl Freeze for BootInfo","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Freeze for AcpiTable&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Freeze for Fuse","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Freeze for Cmd&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Freeze,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Freeze for Rsp&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Freeze,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl Freeze for fuse_in_header","synthetic":true,"types":[]},{"text":"impl Freeze for fuse_out_header","synthetic":true,"types":[]},{"text":"impl Freeze for fuse_init_in","synthetic":true,"types":[]},{"text":"impl Freeze for fuse_init_out","synthetic":true,"types":[]},{"text":"impl Freeze for fuse_read_in","synthetic":true,"types":[]},{"text":"impl Freeze for fuse_read_out","synthetic":true,"types":[]},{"text":"impl Freeze for fuse_write_in","synthetic":true,"types":[]},{"text":"impl Freeze for fuse_write_out","synthetic":true,"types":[]},{"text":"impl Freeze for fuse_open_in","synthetic":true,"types":[]},{"text":"impl Freeze for fuse_open_out","synthetic":true,"types":[]},{"text":"impl Freeze for fuse_release_in","synthetic":true,"types":[]},{"text":"impl Freeze for fuse_release_out","synthetic":true,"types":[]},{"text":"impl Freeze for fuse_lookup_in","synthetic":true,"types":[]},{"text":"impl Freeze for fuse_entry_out","synthetic":true,"types":[]},{"text":"impl Freeze for fuse_attr","synthetic":true,"types":[]},{"text":"impl Freeze for fuse_unlink_in","synthetic":true,"types":[]},{"text":"impl Freeze for fuse_unlink_out","synthetic":true,"types":[]},{"text":"impl Freeze for fuse_create_in","synthetic":true,"types":[]},{"text":"impl Freeze for fuse_create_out","synthetic":true,"types":[]},{"text":"impl Freeze for Opcode","synthetic":true,"types":[]},{"text":"impl Freeze for ExceptionStackFrame","synthetic":true,"types":[]},{"text":"impl Freeze for IrqStatistics","synthetic":true,"types":[]},{"text":"impl Freeze for PciAdapter","synthetic":true,"types":[]},{"text":"impl Freeze for IOBar","synthetic":true,"types":[]},{"text":"impl Freeze for MemoryBar","synthetic":true,"types":[]},{"text":"impl Freeze for PciClassCode","synthetic":true,"types":[]},{"text":"impl Freeze for PciNetworkControllerSubclass","synthetic":true,"types":[]},{"text":"impl Freeze for PciBar","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; !Freeze for PciDriver&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Freeze for PerCoreInnerVariables","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Freeze for PerCoreVariable&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Freeze,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl Freeze for XSaveLegacyRegion","synthetic":true,"types":[]},{"text":"impl Freeze for XSaveHeader","synthetic":true,"types":[]},{"text":"impl Freeze for XSaveAVXState","synthetic":true,"types":[]},{"text":"impl Freeze for XSaveLWPState","synthetic":true,"types":[]},{"text":"impl Freeze for XSaveBndregs","synthetic":true,"types":[]},{"text":"impl Freeze for XSaveBndcsr","synthetic":true,"types":[]},{"text":"impl Freeze for FPUState","synthetic":true,"types":[]},{"text":"impl Freeze for BootStack","synthetic":true,"types":[]},{"text":"impl Freeze for CommonStack","synthetic":true,"types":[]},{"text":"impl Freeze for TaskTLS","synthetic":true,"types":[]},{"text":"impl Freeze for TaskStacks","synthetic":true,"types":[]},{"text":"impl Freeze for SerialPort","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; !Freeze for Virtq&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Freeze for virtq_desc_raw","synthetic":true,"types":[]},{"text":"impl Freeze for virtio_pci_notify_cap","synthetic":true,"types":[]},{"text":"impl Freeze for virtio_pci_common_cfg","synthetic":true,"types":[]},{"text":"impl Freeze for VirtioNotification","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Freeze for VirtioFsDriver&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Freeze for VirtioNetDriver&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Freeze for PageTableEntryFlags","synthetic":true,"types":[]},{"text":"impl Freeze for PageTableEntry","synthetic":true,"types":[]},{"text":"impl Freeze for BasePageSize","synthetic":true,"types":[]},{"text":"impl Freeze for LargePageSize","synthetic":true,"types":[]},{"text":"impl Freeze for HugePageSize","synthetic":true,"types":[]},{"text":"impl Freeze for Filesystem","synthetic":true,"types":[]},{"text":"impl Freeze for FilePerms","synthetic":true,"types":[]},{"text":"impl Freeze for FileError","synthetic":true,"types":[]},{"text":"impl Freeze for SeekWhence","synthetic":true,"types":[]}];
implementors["log"] = [{"text":"impl&lt;'a&gt; Freeze for Record&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Freeze for RecordBuilder&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Freeze for Metadata&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Freeze for MetadataBuilder&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Freeze for SetLoggerError","synthetic":true,"types":[]},{"text":"impl Freeze for ParseLevelError","synthetic":true,"types":[]},{"text":"impl Freeze for Level","synthetic":true,"types":[]},{"text":"impl Freeze for LevelFilter","synthetic":true,"types":[]}];
implementors["multiboot"] = [{"text":"impl&lt;'a, F&gt; Freeze for Multiboot&lt;'a, F&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;F: Freeze,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl Freeze for BootDevice","synthetic":true,"types":[]},{"text":"impl Freeze for MemoryEntry","synthetic":true,"types":[]},{"text":"impl&lt;'a, F&gt; Freeze for MemoryMapIter&lt;'a, F&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Freeze for Module&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a, F&gt; Freeze for ModuleIter&lt;'a, F&gt;","synthetic":true,"types":[]},{"text":"impl Freeze for MemoryType","synthetic":true,"types":[]}];
implementors["num_complex"] = [{"text":"impl&lt;T&gt; Freeze for Complex&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Freeze,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;E&gt; Freeze for ParseComplexError&lt;E&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;E: Freeze,&nbsp;</span>","synthetic":true,"types":[]}];
implementors["num_integer"] = [{"text":"impl&lt;A&gt; Freeze for ExtendedGcd&lt;A&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;A: Freeze,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Freeze for IterBinomial&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Freeze,&nbsp;</span>","synthetic":true,"types":[]}];
implementors["num_iter"] = [{"text":"impl&lt;A&gt; Freeze for Range&lt;A&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;A: Freeze,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;A&gt; Freeze for RangeInclusive&lt;A&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;A: Freeze,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;A&gt; Freeze for RangeStep&lt;A&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;A: Freeze,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;A&gt; Freeze for RangeStepInclusive&lt;A&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;A: Freeze,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;A&gt; Freeze for RangeFrom&lt;A&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;A: Freeze,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;A&gt; Freeze for RangeStepFrom&lt;A&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;A: Freeze,&nbsp;</span>","synthetic":true,"types":[]}];
implementors["num_rational"] = [{"text":"impl&lt;T&gt; Freeze for Ratio&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Freeze,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl Freeze for ParseRatioError","synthetic":true,"types":[]}];
implementors["num_traits"] = [{"text":"impl Freeze for ParseFloatError","synthetic":true,"types":[]},{"text":"impl Freeze for FloatErrorKind","synthetic":true,"types":[]}];
implementors["raw_cpuid"] = [{"text":"impl Freeze for CpuId","synthetic":true,"types":[]},{"text":"impl Freeze for CpuIdResult","synthetic":true,"types":[]},{"text":"impl Freeze for VendorInfo","synthetic":true,"types":[]},{"text":"impl Freeze for CacheInfoIter","synthetic":true,"types":[]},{"text":"impl Freeze for CacheInfo","synthetic":true,"types":[]},{"text":"impl Freeze for ProcessorSerial","synthetic":true,"types":[]},{"text":"impl Freeze for FeatureInfo","synthetic":true,"types":[]},{"text":"impl Freeze for CacheParametersIter","synthetic":true,"types":[]},{"text":"impl Freeze for CacheParameter","synthetic":true,"types":[]},{"text":"impl Freeze for MonitorMwaitInfo","synthetic":true,"types":[]},{"text":"impl Freeze for ThermalPowerInfo","synthetic":true,"types":[]},{"text":"impl Freeze for ExtendedFeatures","synthetic":true,"types":[]},{"text":"impl Freeze for DirectCacheAccessInfo","synthetic":true,"types":[]},{"text":"impl Freeze for PerformanceMonitoringInfo","synthetic":true,"types":[]},{"text":"impl Freeze for ExtendedTopologyIter","synthetic":true,"types":[]},{"text":"impl Freeze for ExtendedTopologyLevel","synthetic":true,"types":[]},{"text":"impl Freeze for ExtendedStateInfo","synthetic":true,"types":[]},{"text":"impl Freeze for ExtendedStateIter","synthetic":true,"types":[]},{"text":"impl Freeze for ExtendedState","synthetic":true,"types":[]},{"text":"impl Freeze for RdtMonitoringInfo","synthetic":true,"types":[]},{"text":"impl Freeze for L3MonitoringInfo","synthetic":true,"types":[]},{"text":"impl Freeze for RdtAllocationInfo","synthetic":true,"types":[]},{"text":"impl Freeze for L3CatInfo","synthetic":true,"types":[]},{"text":"impl Freeze for L2CatInfo","synthetic":true,"types":[]},{"text":"impl Freeze for MemBwAllocationInfo","synthetic":true,"types":[]},{"text":"impl Freeze for SgxInfo","synthetic":true,"types":[]},{"text":"impl Freeze for SgxSectionIter","synthetic":true,"types":[]},{"text":"impl Freeze for EpcSection","synthetic":true,"types":[]},{"text":"impl Freeze for ProcessorTraceInfo","synthetic":true,"types":[]},{"text":"impl Freeze for TscInfo","synthetic":true,"types":[]},{"text":"impl Freeze for ProcessorFrequencyInfo","synthetic":true,"types":[]},{"text":"impl Freeze for DatIter","synthetic":true,"types":[]},{"text":"impl Freeze for DatInfo","synthetic":true,"types":[]},{"text":"impl Freeze for SoCVendorInfo","synthetic":true,"types":[]},{"text":"impl Freeze for SoCVendorAttributesIter","synthetic":true,"types":[]},{"text":"impl Freeze for SoCVendorBrand","synthetic":true,"types":[]},{"text":"impl Freeze for HypervisorInfo","synthetic":true,"types":[]},{"text":"impl Freeze for ExtendedFunctionInfo","synthetic":true,"types":[]},{"text":"impl Freeze for MemoryEncryptionInfo","synthetic":true,"types":[]},{"text":"impl Freeze for CacheInfoType","synthetic":true,"types":[]},{"text":"impl Freeze for CacheType","synthetic":true,"types":[]},{"text":"impl Freeze for TopologyType","synthetic":true,"types":[]},{"text":"impl Freeze for SgxSectionInfo","synthetic":true,"types":[]},{"text":"impl Freeze for DatType","synthetic":true,"types":[]},{"text":"impl Freeze for Hypervisor","synthetic":true,"types":[]},{"text":"impl Freeze for L2Associativity","synthetic":true,"types":[]}];
implementors["x86"] = [{"text":"impl Freeze for Ring","synthetic":true,"types":[]},{"text":"impl Freeze for EFlags","synthetic":true,"types":[]},{"text":"impl Freeze for TaskStateSegment","synthetic":true,"types":[]},{"text":"impl Freeze for PAddr","synthetic":true,"types":[]},{"text":"impl Freeze for VAddr","synthetic":true,"types":[]},{"text":"impl Freeze for Page","synthetic":true,"types":[]},{"text":"impl Freeze for LargePage","synthetic":true,"types":[]},{"text":"impl Freeze for HugePage","synthetic":true,"types":[]},{"text":"impl Freeze for PML4Flags","synthetic":true,"types":[]},{"text":"impl Freeze for PML4Entry","synthetic":true,"types":[]},{"text":"impl Freeze for PDPTFlags","synthetic":true,"types":[]},{"text":"impl Freeze for PDPTEntry","synthetic":true,"types":[]},{"text":"impl Freeze for PDFlags","synthetic":true,"types":[]},{"text":"impl Freeze for PDEntry","synthetic":true,"types":[]},{"text":"impl Freeze for PTFlags","synthetic":true,"types":[]},{"text":"impl Freeze for PTEntry","synthetic":true,"types":[]},{"text":"impl Freeze for RFlags","synthetic":true,"types":[]},{"text":"impl Freeze for Descriptor64","synthetic":true,"types":[]},{"text":"impl Freeze for TaskStateSegment","synthetic":true,"types":[]},{"text":"impl Freeze for Icr","synthetic":true,"types":[]},{"text":"impl Freeze for DeliveryMode","synthetic":true,"types":[]},{"text":"impl Freeze for DestinationMode","synthetic":true,"types":[]},{"text":"impl Freeze for DeliveryStatus","synthetic":true,"types":[]},{"text":"impl Freeze for Level","synthetic":true,"types":[]},{"text":"impl Freeze for TriggerMode","synthetic":true,"types":[]},{"text":"impl Freeze for DestinationShorthand","synthetic":true,"types":[]},{"text":"impl Freeze for ApicId","synthetic":true,"types":[]},{"text":"impl Freeze for IoApic","synthetic":true,"types":[]},{"text":"impl Freeze for X2APIC","synthetic":true,"types":[]},{"text":"impl Freeze for XAPIC","synthetic":true,"types":[]},{"text":"impl Freeze for Cr0","synthetic":true,"types":[]},{"text":"impl Freeze for Cr4","synthetic":true,"types":[]},{"text":"impl Freeze for Xcr0","synthetic":true,"types":[]},{"text":"impl&lt;Entry&gt; Freeze for DescriptorTablePointer&lt;Entry&gt;","synthetic":true,"types":[]},{"text":"impl Freeze for InterruptDescription","synthetic":true,"types":[]},{"text":"impl Freeze for PageFaultError","synthetic":true,"types":[]},{"text":"impl Freeze for SegmentSelector","synthetic":true,"types":[]},{"text":"impl Freeze for DescriptorBuilder","synthetic":true,"types":[]},{"text":"impl Freeze for Descriptor","synthetic":true,"types":[]},{"text":"impl Freeze for SystemDescriptorTypes64","synthetic":true,"types":[]},{"text":"impl Freeze for SystemDescriptorTypes32","synthetic":true,"types":[]},{"text":"impl Freeze for DataSegmentType","synthetic":true,"types":[]},{"text":"impl Freeze for CodeSegmentType","synthetic":true,"types":[]},{"text":"impl Freeze for VmFail","synthetic":true,"types":[]},{"text":"impl Freeze for PinbasedControls","synthetic":true,"types":[]},{"text":"impl Freeze for PrimaryControls","synthetic":true,"types":[]},{"text":"impl Freeze for SecondaryControls","synthetic":true,"types":[]},{"text":"impl Freeze for EntryControls","synthetic":true,"types":[]},{"text":"impl Freeze for ExitControls","synthetic":true,"types":[]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()