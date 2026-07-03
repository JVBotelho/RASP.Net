using System.Runtime.CompilerServices;

// Rasp.Core is strong-named (see Rasp.Core.csproj) so Rasp.Native.Profiler can pin the
// AssemblyRef it emits for RaspTaintSensor by public key token instead of resolving by
// simple name alone. Strong-named assemblies can only grant InternalsVisibleTo to other
// strong-named assemblies, referenced here by their public key (not just name) - the
// friend assemblies below are signed with the same src/Rasp.Core/RaspCore.snk key pair.
[assembly: InternalsVisibleTo("Rasp.Core.Tests, PublicKey=00240000048000009400000006020000002400005253413100040000010001000508af74d0bcf9c0a5c9a25ce6f4436596f85e106e14e4af559079f975c83ce9287c2ad87aecd56db455d181ea0ef0f6dc129d5d1954c67576faa0e6e2910e14d6ed3fc0cc7d3e0ab2abf66a338f619b5b4dde01a3de9e6cb7e30a41bfa7494abd6623041d292825f700896a8cfc2c3ee83d92ec6fc2b43ff7f2d34a52c36cce")]

// Rasp.Benchmarks does not use any Rasp.Core internal member (verified: no `internal`
// references in src/Rasp.Benchmarks) and is deliberately left unsigned - see the NoWarn
// CS8002 comment in its .csproj. No IVT grant needed.