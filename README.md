# Reversing Stuff

Collection of reversing stuff that I wrote, or use, that might be mildly
useful to other people.

## IDA Pro Plugins

### Hyper-V Processor Module

[This script](ida_plugins/hyperv_gs_proc.py) is an IDA Pro processor module that
turns `mov XXX, gs:YYY` into `mov XXX, [GSBASE+YYY]`.

It's a bit hacky. Documentation in the header of the script itself.

