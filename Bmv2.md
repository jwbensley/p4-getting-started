# Bmv2

Compile a P4 program using the v1model architecture and generate the bmv2 JSON:

```shell
p4c --target bmv2 --arch v1model --std p4-16 -o /tutorials/exercises/basic/ /tutorials/exercises/basic/basic.p4
```

This outputs two files:

* A file with suffix .p4i, which is the output from running the preprocessor on your P4 program.
* A file with suffix .json that is the JSON file format expected by BMv2 behavioral model simple_switch.

Optionally one can generate the P4Info file for a P4 program by using the –p4runtime-files switch:
```shell
p4c --target bmv2 --arch v1model --std p4-16 -o /tutorials/exercises/basic/ --p4runtime-files basic.p4info.txt /tutorials/exercises/basic/basic.p4
```

Run the simple switch and use the JSON file to emulate the target the basic.p4 program was intended to run on:
```shell
simple_switch -i 0@veth2 -i 1@veth3 -L debug --log-console /tutorials/exercises/basic/basic.json
```
