// A small SDN.XML in the real Treasury layout, for the OFAC tests: a few listed addresses on several chains, plus
// filler entries so the file passes the "at least 100 addresses" sanity check of src/ofac.js.
export const TRON = "TNiq9AXBp9EjUqhDhrwrfvAA8U3GUQZH81";
export const SOL = "42RLPACwZPx3vYYmxSueqsogfynBDqXK298EDsNoyoHi";
export const XRP = "rnXyVQzgxZe7TR1EPzTkGj2jxH4LMJYh66";
export const ETH = "0x098B716B8Aaf21512996dC57EB0615e2383E2f96";
export const BTC = "bc1qjzk63wwatq2f638psymq3qapn00aqgksyx56l3t8eg7zuuccwasq498khf";

const id = (uid, currency, address) => `
      <id>
        <uid>${uid}</uid>
        <idType>Digital Currency Address - ${currency}</idType>
        <idNumber>${address}</idNumber>
      </id>`;
const entry = (uid, { first, last, type = "Entity", programs, ids }) => `
  <sdnEntry>
    <uid>${uid}</uid>${first ? `\n    <firstName>${first}</firstName>` : ""}
    <lastName>${last}</lastName>
    <sdnType>${type}</sdnType>
    <programList>${programs.map((p) => `\n      <program>${p}</program>`).join("")}
    </programList>
    <idList>
      <id>
        <uid>1</uid>
        <idType>Email Address</idType>
        <idNumber>someone@example.com</idNumber>
      </id>${ids.join("")}
    </idList>
  </sdnEntry>`;
// Filler entries so the file passes the "at least 100 addresses" sanity check.
const filler = Array.from({ length: 110 }, (_, i) => entry(900000 + i, { last: `FILLER ${i}`, programs: ["CYBER2"], ids: [id(800000 + i, "XBT", `1Filler${String(i).padStart(26, "x")}`)] }));
export const SDN_XML = `<?xml version="1.0" standalone="yes"?>
<sdnList xmlns="https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/XML">
  <publshInformation>
    <Publish_Date>10/09/2026</Publish_Date>
    <Record_Count>19416</Record_Count>
  </publshInformation>
  ${entry(36, { last: "AEROCARIBBEAN AIRLINES", programs: ["CUBA"], ids: [] })}
  ${entry(4632, { last: "BANK MARKAZI JOMHOURI ISLAMI IRAN", programs: ["IRAN", "SDGT"], ids: [id(10, "TRX", TRON)] })}
  ${entry(56360, { first: "Rolan", last: "SOKOLOVSKI", type: "Individual", programs: ["ILLICIT-DRUGS-EO14059"], ids: [id(11, "SOL", SOL), id(12, "ETH", "0x5d5b5dafecbf31bdb08bfd3edad4f2694372d0ef")] })}
  ${entry(33854, { last: "CHATEX", programs: ["CYBER2"], ids: [id(13, "XRP", XRP)] })}
  ${entry(27307, { last: "LAZARUS GROUP", programs: ["DPRK3"], ids: [id(14, "ETH", ETH.toLowerCase()), id(15, "USDT", ETH.toLowerCase())] })}
  ${entry(58287, { last: "SHPS SHELBIT &amp; CO", programs: ["SDGT"], ids: [id(16, "XBT", BTC)] })}
  ${filler.join("")}
</sdnList>`;

