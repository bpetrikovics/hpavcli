# hpavcli - Powerline (HomePlug AV) Utility


[![CodeQL](https://github.com/bpetrikovics/shelly-ota/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/bpetrikovics/hpavcli/actions/workflows/codeql-analysis.yml)

**WARNING - WORK IN PROGRESS**

**hpavcli** is (will be) a command line utility to communicate with Powerline (HPAV) devices from various brands, written in Python.

It all began when I bought a pair of Powerline adapters, and wanted to be able to monitor them, keep an eye on the
network speeds etc. Then I realized that the vendor only provided a pretty useless Windows GUI utility and that the
tools I've found on GitHub don't really work with my devices. After a bit of an investigation I've found two projects
(see below) that pointed me in the right direction, and I've learnt that as always, standards are good because everyone
can have their own. Apparently my TP-Link devices only implemented a small basic subset of the HomePlug AV standard,
just to have the rest of the functionality implemented over an undocumented (well, at least publicly...) vendor-specific
protocol.

So I used the public HPAV 2.1 documentation and hints from some GitHub repositories to put together my own little tool.
My ultimate goal was to a.) be able to detect HPAV devices on my LAN, and b.) have a means for monitoring their basic
properties, including the actual link speed between them.

This is a work in progress as I'm experimenting with the protocol and trying to find those bits and pieces that work with
my adapters and give me useful information/functions. The code may or may not work for you, and it could possibly eat
your device for breakfast. Any feedback is welcome though.

HPAV2.1 protocol documentation:
* https://docbox.etsi.org/Reference/homeplug_av21/homeplug_av21_specification_final_public.pdf

Sources I used:
* https://github.com/serock/pla-util/wiki
* https://docs.rs/crate/powerline/0.1.0/source/

NOTE: The code is only confirmed to run on Linux. Definitely won't work with Mac and BSD due to the lack of AF_PACKET
("raw Ethernet") implementation. Might work on Windows, but never tried. Until then, it checks for Linux and refuses
to run otherwise.
