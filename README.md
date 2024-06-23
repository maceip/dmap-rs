This is the state of the dmap repo shortly after deployment.
Here is the dmap address: 0x90949c9937A11BA943C7A72C3FA073a37E3FdD96

We are keeping this repo here for reference but development is now
fragmented across many repos. There is no 'official' dmap project repo,
dmap is defined by one simple object that treats every caller identically.

------------

`dmap` is a minimalist key-value store built to solve the problem
that DNS and the certificate authority PKI is backdoored.

The main thing about dmap is that it has a native concept
of immutability, while still allowing user-defined registry logic.

`dpath` is a path format used for traversing the dmap registries.
This path format also has a concept of 'verify immutable',
and the syntax is design to be discerned easily at a glance.

```
:pack:rico.latest
          ^  warning, the value of this path is mutable, starting here

:pack:rico:v2
          ^  here you can see it is locked
```

One of the core design motives for dmap was to make it as simple as possible
to write lightweight / embeddable state proof verifiers.

By keeping all state in one contract object and making user registries call
into this one object, merkle proofs for traversals of subregistries
are compact and do not require spinning up an EVM.

Locked entries can safely be cached, assuming that Ethereum's security properties hold.
It is a canary in the coal mine for the rest of the system -- if you can't depend
on locked dmap values, you can't depend on Ethereum.

The mechanism design of the root and free registries is intentionally "naive",
but because it is neutral and final, it is good enough to build on.
We want everyone to think through how the incentives will reduce,
and create good rules for top-level namezones.