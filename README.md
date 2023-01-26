# grack

Like [`gron`](https://github.com/tomnomnom/gron), but for `msgpack`.

Arguments are parsed from the first parameter as json, which can be partially
specified.

```
> grack -h

Failed to parse input: -h
Default settings:
{
  "hide_array_index": false,
  "hide_map_index": false,
  "inline_map_key": true,
  "inline_array": true,
  "inline_map": true,
  "root_prefix": "root"
}

Keys:
- hide_array_index, ha:     bool   = false
- hide_map_index, hm:       bool   = false
- inline_map_key, ik:       bool   = true
- inline_array, ia:         bool   = true
- inline_map, im:           bool   = true
- root_prefix, p:           string = "root"
Error: Unexpected character: h at (1:2)
```

## Example

```
> cat blob | grack '{"p":".","hm":false,"ik":false}'
root = [0u0, 100u0, 1.23f32, {}m0@0]a0@4
```

# Why?

For diffing msgpack blobs and inspecting them.
