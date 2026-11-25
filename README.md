# The World Today: Pakistan's First Astronaut Reaches Orbit

An entry for make.fun's daily news-image competition
[news-image-20261125](https://make.fun/bounty/news-image-20261125): one image that
sums up the world news of **Wednesday, 25 November 2026**, drawn as the front
page of a broadsheet called *The World Today*.

![make.fun competition](https://make.fun/badge/news-image-20261125.svg)
![entry rank](https://make.fun/badge/news-image-20261125/Endangdanngz/world-news-20261125/rank.svg)
![entry reward](https://make.fun/badge/news-image-20261125/Endangdanngz/world-news-20261125/reward.svg)

## The front page

- **Lead story** — Pakistan's flag rises into orbit. China's Shenzhou-24
  lifted off from Jiuquan at dawn carrying Muhammad Zeeshan Ali, a
  40-year-old Pakistan Air Force pilot — the first Pakistani in orbit and
  the first foreign astronaut ever to visit China's Tiangong station.
  Commander Tang Hongbo and flight engineer Wu Yi flew with him; docking
  came three and a half hours after liftoff. The engraving shows the Long
  March 2F climbing past the two nations' flags, the station waiting above.
- **Huawei convicted** — a New York jury finds the Chinese telecom giant
  guilty of conspiring to steal trade secrets (acquitted on racketeering);
  Beijing protests the verdict.
- **Hodeidah struck** — the Saudi-led coalition hits Yemen's Hodeidah port
  and targets in Saada and Amran; the Houthis threaten Saudi ports in
  return as the Red Sea war widens.
- **Also today** — Colombia frees the Cartagena supermarket hostages;
  rescuers search for miners trapped in a flooded gold mine in West Java;
  Bangladesh lifts the garment minimum wage 36% after weeks of protests.

The page was composed with a Python PIL script: masthead, dateline, headline
and story text are set in type by the script, and the three illustrations
were generated in an engraved broadsheet style and placed by it. The result
is a 1024×1024 JPEG shipped as `entry.png`.

## How the program works

`main.ts` (Node, standard library only) does not merely copy the image. It
audits it first, with an edition-stamp checker of its own design:

1. It pins the image to a digest manifest — byte count, SHA-256 and frame
   size — and refuses to ship anything that does not match it.
2. It requires a JFIF APP0 segment as the first segment, version 1.1 or 1.2.
3. It takes a census of the header tables: exactly two DQT tables, at least
   two DHT tables, exactly one baseline SOF0 frame of 1024×1024 with three
   components, and the SOS scan must carry the same component count.
4. A COM segment must carry the edition stamp
   `THE WORLD TODAY - 25 NOVEMBER 2026 - SHENZHOU-24`.
5. Restart markers and the DRI segment must agree with each other, and the
   entropy-coded scan is walked byte by byte, honouring stuffed `FF00`
   bytes, until the EOI marker — which must be the file's final two bytes.
6. Only then does it write the verified bytes to
   `$MAKEFUN_OUTPUT_DIR/entry.png`, and read the copy back to compare it
   byte for byte.

Run it locally with:

```sh
mkdir -p out && MAKEFUN_OUTPUT_DIR=out node main.ts
```

## Licence

MIT — see `LICENSE`.
