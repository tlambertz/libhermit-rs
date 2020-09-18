(function() {var implementors = {};
implementors["hermit"] = [{"text":"impl&lt;'a&gt; Send for SpinlockContainer&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Send for SpinlockIrqSaveContainer&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Send for itimerval","synthetic":true,"types":[]},{"text":"impl Send for timespec","synthetic":true,"types":[]},{"text":"impl Send for timeval","synthetic":true,"types":[]},{"text":"impl Send for BootInfo","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Send for AcpiTable&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Send for Fuse","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Send for Cmd&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Send,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Send for Rsp&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Send,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl Send for fuse_in_header","synthetic":true,"types":[]},{"text":"impl Send for fuse_out_header","synthetic":true,"types":[]},{"text":"impl Send for fuse_init_in","synthetic":true,"types":[]},{"text":"impl Send for fuse_init_out","synthetic":true,"types":[]},{"text":"impl Send for fuse_read_in","synthetic":true,"types":[]},{"text":"impl Send for fuse_read_out","synthetic":true,"types":[]},{"text":"impl Send for fuse_write_in","synthetic":true,"types":[]},{"text":"impl Send for fuse_write_out","synthetic":true,"types":[]},{"text":"impl Send for fuse_open_in","synthetic":true,"types":[]},{"text":"impl Send for fuse_open_out","synthetic":true,"types":[]},{"text":"impl Send for fuse_release_in","synthetic":true,"types":[]},{"text":"impl Send for fuse_release_out","synthetic":true,"types":[]},{"text":"impl Send for fuse_lookup_in","synthetic":true,"types":[]},{"text":"impl Send for fuse_entry_out","synthetic":true,"types":[]},{"text":"impl Send for fuse_attr","synthetic":true,"types":[]},{"text":"impl Send for fuse_unlink_in","synthetic":true,"types":[]},{"text":"impl Send for fuse_unlink_out","synthetic":true,"types":[]},{"text":"impl Send for fuse_create_in","synthetic":true,"types":[]},{"text":"impl Send for fuse_create_out","synthetic":true,"types":[]},{"text":"impl Send for Opcode","synthetic":true,"types":[]},{"text":"impl Send for ExceptionStackFrame","synthetic":true,"types":[]},{"text":"impl Send for IrqStatistics","synthetic":true,"types":[]},{"text":"impl Send for PciAdapter","synthetic":true,"types":[]},{"text":"impl Send for IOBar","synthetic":true,"types":[]},{"text":"impl Send for MemoryBar","synthetic":true,"types":[]},{"text":"impl Send for PciClassCode","synthetic":true,"types":[]},{"text":"impl Send for PciNetworkControllerSubclass","synthetic":true,"types":[]},{"text":"impl Send for PciBar","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; !Send for PciDriver&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl !Send for PerCoreInnerVariables","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Send for PerCoreVariable&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Send,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl Send for XSaveLegacyRegion","synthetic":true,"types":[]},{"text":"impl Send for XSaveHeader","synthetic":true,"types":[]},{"text":"impl Send for XSaveAVXState","synthetic":true,"types":[]},{"text":"impl Send for XSaveLWPState","synthetic":true,"types":[]},{"text":"impl Send for XSaveBndregs","synthetic":true,"types":[]},{"text":"impl Send for XSaveBndcsr","synthetic":true,"types":[]},{"text":"impl Send for FPUState","synthetic":true,"types":[]},{"text":"impl Send for BootStack","synthetic":true,"types":[]},{"text":"impl Send for CommonStack","synthetic":true,"types":[]},{"text":"impl Send for TaskTLS","synthetic":true,"types":[]},{"text":"impl Send for TaskStacks","synthetic":true,"types":[]},{"text":"impl Send for SerialPort","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; !Send for Virtq&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Send for virtq_desc_raw","synthetic":true,"types":[]},{"text":"impl Send for virtio_pci_notify_cap","synthetic":true,"types":[]},{"text":"impl Send for virtio_pci_common_cfg","synthetic":true,"types":[]},{"text":"impl !Send for VirtioNotification","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; !Send for VirtioFsDriver&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; !Send for VirtioNetDriver&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Send for PageTableEntryFlags","synthetic":true,"types":[]},{"text":"impl Send for PageTableEntry","synthetic":true,"types":[]},{"text":"impl Send for BasePageSize","synthetic":true,"types":[]},{"text":"impl Send for LargePageSize","synthetic":true,"types":[]},{"text":"impl Send for HugePageSize","synthetic":true,"types":[]},{"text":"impl Send for Filesystem","synthetic":true,"types":[]},{"text":"impl Send for FilePerms","synthetic":true,"types":[]},{"text":"impl Send for FileError","synthetic":true,"types":[]},{"text":"impl Send for SeekWhence","synthetic":true,"types":[]}];
implementors["log"] = [{"text":"impl&lt;'a&gt; !Send for Record&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; !Send for RecordBuilder&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Send for Metadata&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Send for MetadataBuilder&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl Send for SetLoggerError","synthetic":true,"types":[]},{"text":"impl Send for ParseLevelError","synthetic":true,"types":[]},{"text":"impl Send for Level","synthetic":true,"types":[]},{"text":"impl Send for LevelFilter","synthetic":true,"types":[]}];
implementors["multiboot"] = [{"text":"impl&lt;'a, F&gt; Send for Multiboot&lt;'a, F&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;F: Send,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl Send for BootDevice","synthetic":true,"types":[]},{"text":"impl Send for MemoryEntry","synthetic":true,"types":[]},{"text":"impl&lt;'a, F&gt; Send for MemoryMapIter&lt;'a, F&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;F: Sync,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;'a&gt; Send for Module&lt;'a&gt;","synthetic":true,"types":[]},{"text":"impl&lt;'a, F&gt; Send for ModuleIter&lt;'a, F&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;F: Sync,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl Send for MemoryType","synthetic":true,"types":[]}];
implementors["num_complex"] = [{"text":"impl&lt;T&gt; Send for Complex&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Send,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;E&gt; Send for ParseComplexError&lt;E&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;E: Send,&nbsp;</span>","synthetic":true,"types":[]}];
implementors["num_integer"] = [{"text":"impl&lt;A&gt; Send for ExtendedGcd&lt;A&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;A: Send,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;T&gt; Send for IterBinomial&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Send,&nbsp;</span>","synthetic":true,"types":[]}];
implementors["num_iter"] = [{"text":"impl&lt;A&gt; Send for Range&lt;A&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;A: Send,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;A&gt; Send for RangeInclusive&lt;A&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;A: Send,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;A&gt; Send for RangeStep&lt;A&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;A: Send,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;A&gt; Send for RangeStepInclusive&lt;A&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;A: Send,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;A&gt; Send for RangeFrom&lt;A&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;A: Send,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl&lt;A&gt; Send for RangeStepFrom&lt;A&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;A: Send,&nbsp;</span>","synthetic":true,"types":[]}];
implementors["num_rational"] = [{"text":"impl&lt;T&gt; Send for Ratio&lt;T&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;T: Send,&nbsp;</span>","synthetic":true,"types":[]},{"text":"impl Send for ParseRatioError","synthetic":true,"types":[]}];
implementors["num_traits"] = [{"text":"impl Send for ParseFloatError","synthetic":true,"types":[]},{"text":"impl Send for FloatErrorKind","synthetic":true,"types":[]}];
implementors["raw_cpuid"] = [{"text":"impl Send for CpuId","synthetic":true,"types":[]},{"text":"impl Send for CpuIdResult","synthetic":true,"types":[]},{"text":"impl Send for VendorInfo","synthetic":true,"types":[]},{"text":"impl Send for CacheInfoIter","synthetic":true,"types":[]},{"text":"impl Send for CacheInfo","synthetic":true,"types":[]},{"text":"impl Send for ProcessorSerial","synthetic":true,"types":[]},{"text":"impl Send for FeatureInfo","synthetic":true,"types":[]},{"text":"impl Send for CacheParametersIter","synthetic":true,"types":[]},{"text":"impl Send for CacheParameter","synthetic":true,"types":[]},{"text":"impl Send for MonitorMwaitInfo","synthetic":true,"types":[]},{"text":"impl Send for ThermalPowerInfo","synthetic":true,"types":[]},{"text":"impl Send for ExtendedFeatures","synthetic":true,"types":[]},{"text":"impl Send for DirectCacheAccessInfo","synthetic":true,"types":[]},{"text":"impl Send for PerformanceMonitoringInfo","synthetic":true,"types":[]},{"text":"impl Send for ExtendedTopologyIter","synthetic":true,"types":[]},{"text":"impl Send for ExtendedTopologyLevel","synthetic":true,"types":[]},{"text":"impl Send for ExtendedStateInfo","synthetic":true,"types":[]},{"text":"impl Send for ExtendedStateIter","synthetic":true,"types":[]},{"text":"impl Send for ExtendedState","synthetic":true,"types":[]},{"text":"impl Send for RdtMonitoringInfo","synthetic":true,"types":[]},{"text":"impl Send for L3MonitoringInfo","synthetic":true,"types":[]},{"text":"impl Send for RdtAllocationInfo","synthetic":true,"types":[]},{"text":"impl Send for L3CatInfo","synthetic":true,"types":[]},{"text":"impl Send for L2CatInfo","synthetic":true,"types":[]},{"text":"impl Send for MemBwAllocationInfo","synthetic":true,"types":[]},{"text":"impl Send for SgxInfo","synthetic":true,"types":[]},{"text":"impl Send for SgxSectionIter","synthetic":true,"types":[]},{"text":"impl Send for EpcSection","synthetic":true,"types":[]},{"text":"impl Send for ProcessorTraceInfo","synthetic":true,"types":[]},{"text":"impl Send for TscInfo","synthetic":true,"types":[]},{"text":"impl Send for ProcessorFrequencyInfo","synthetic":true,"types":[]},{"text":"impl Send for DatIter","synthetic":true,"types":[]},{"text":"impl Send for DatInfo","synthetic":true,"types":[]},{"text":"impl Send for SoCVendorInfo","synthetic":true,"types":[]},{"text":"impl Send for SoCVendorAttributesIter","synthetic":true,"types":[]},{"text":"impl Send for SoCVendorBrand","synthetic":true,"types":[]},{"text":"impl Send for HypervisorInfo","synthetic":true,"types":[]},{"text":"impl Send for ExtendedFunctionInfo","synthetic":true,"types":[]},{"text":"impl Send for MemoryEncryptionInfo","synthetic":true,"types":[]},{"text":"impl Send for CacheInfoType","synthetic":true,"types":[]},{"text":"impl Send for CacheType","synthetic":true,"types":[]},{"text":"impl Send for TopologyType","synthetic":true,"types":[]},{"text":"impl Send for SgxSectionInfo","synthetic":true,"types":[]},{"text":"impl Send for DatType","synthetic":true,"types":[]},{"text":"impl Send for Hypervisor","synthetic":true,"types":[]},{"text":"impl Send for L2Associativity","synthetic":true,"types":[]}];
implementors["x86"] = [{"text":"impl Send for Ring","synthetic":true,"types":[]},{"text":"impl Send for EFlags","synthetic":true,"types":[]},{"text":"impl Send for TaskStateSegment","synthetic":true,"types":[]},{"text":"impl Send for PAddr","synthetic":true,"types":[]},{"text":"impl Send for VAddr","synthetic":true,"types":[]},{"text":"impl Send for Page","synthetic":true,"types":[]},{"text":"impl Send for LargePage","synthetic":true,"types":[]},{"text":"impl Send for HugePage","synthetic":true,"types":[]},{"text":"impl Send for PML4Flags","synthetic":true,"types":[]},{"text":"impl Send for PML4Entry","synthetic":true,"types":[]},{"text":"impl Send for PDPTFlags","synthetic":true,"types":[]},{"text":"impl Send for PDPTEntry","synthetic":true,"types":[]},{"text":"impl Send for PDFlags","synthetic":true,"types":[]},{"text":"impl Send for PDEntry","synthetic":true,"types":[]},{"text":"impl Send for PTFlags","synthetic":true,"types":[]},{"text":"impl Send for PTEntry","synthetic":true,"types":[]},{"text":"impl Send for RFlags","synthetic":true,"types":[]},{"text":"impl Send for Descriptor64","synthetic":true,"types":[]},{"text":"impl Send for TaskStateSegment","synthetic":true,"types":[]},{"text":"impl Send for Icr","synthetic":true,"types":[]},{"text":"impl Send for DeliveryMode","synthetic":true,"types":[]},{"text":"impl Send for DestinationMode","synthetic":true,"types":[]},{"text":"impl Send for DeliveryStatus","synthetic":true,"types":[]},{"text":"impl Send for Level","synthetic":true,"types":[]},{"text":"impl Send for TriggerMode","synthetic":true,"types":[]},{"text":"impl Send for DestinationShorthand","synthetic":true,"types":[]},{"text":"impl Send for ApicId","synthetic":true,"types":[]},{"text":"impl !Send for IoApic","synthetic":true,"types":[]},{"text":"impl Send for X2APIC","synthetic":true,"types":[]},{"text":"impl Send for XAPIC","synthetic":true,"types":[]},{"text":"impl Send for Cr0","synthetic":true,"types":[]},{"text":"impl Send for Cr4","synthetic":true,"types":[]},{"text":"impl Send for Xcr0","synthetic":true,"types":[]},{"text":"impl&lt;Entry&gt; !Send for DescriptorTablePointer&lt;Entry&gt;","synthetic":true,"types":[]},{"text":"impl Send for InterruptDescription","synthetic":true,"types":[]},{"text":"impl Send for PageFaultError","synthetic":true,"types":[]},{"text":"impl Send for SegmentSelector","synthetic":true,"types":[]},{"text":"impl Send for DescriptorBuilder","synthetic":true,"types":[]},{"text":"impl Send for Descriptor","synthetic":true,"types":[]},{"text":"impl Send for SystemDescriptorTypes64","synthetic":true,"types":[]},{"text":"impl Send for SystemDescriptorTypes32","synthetic":true,"types":[]},{"text":"impl Send for DataSegmentType","synthetic":true,"types":[]},{"text":"impl Send for CodeSegmentType","synthetic":true,"types":[]},{"text":"impl Send for VmFail","synthetic":true,"types":[]},{"text":"impl Send for PinbasedControls","synthetic":true,"types":[]},{"text":"impl Send for PrimaryControls","synthetic":true,"types":[]},{"text":"impl Send for SecondaryControls","synthetic":true,"types":[]},{"text":"impl Send for EntryControls","synthetic":true,"types":[]},{"text":"impl Send for ExitControls","synthetic":true,"types":[]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()