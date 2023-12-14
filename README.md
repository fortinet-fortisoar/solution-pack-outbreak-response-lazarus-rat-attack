# Release Information 

- **Version**: 1.0.0 
- **Certified**: No 
- **Publisher**: Fortinet 
- **Compatible Version**: FortiSOAR 7.4.0 and later 
 

# Overview 
The **Lazarus RAT Attack**, or **CVE-2021-44228** is a new campaign conducted by the Lazarus Group and employs new DLang-based Remote Access Trojans (RATs) in the wild. The APT groups target manufacturing, agricultural, and physical security companies by exploiting the Log4j vulnerability and use it for initial access leading to a C2 (command and control) channel with the attacker.

The **Outbreak Response Lazarus RAT Attack** solution pack works with the Threat Hunt rules in [Outbreak Response Framework](https://github.com/fortinet-fortisoar/solution-pack-outbreak-response-framework/blob/release/1.0.0/README.md#threat-hunt-rules) solution pack to conduct hunts that identify and help investigate potential Indicators of Compromise (IOCs) associated with this vulnerability within operational environments of *FortiSIEM*, *FortiAnalyzer*, *QRadar*, *Splunk*, and *Azure Log Analytics*.

## Background
Lazarus is an advanced persistent threat (APT) actor allegedly sponsored by the North Korean government. In this particular campaign, Lazarus’s initial access begins with the successful exploitation of **CVE-2021-44228**, the infamous Log4j vulnerability discovered in 2021.

Log4Shell is an unauthenticated remote code execution (RCE) flaw that allows taking complete control over systems using vulnerable versions of the Log4j library. The flaw was discovered as an actively exploited zero-day on December 10, 2021, and its widespread impact, ease of exploitation, and massive security implications acted as an open invitation to threat actors. For more information, refer to the [Log4j2 Vulnerability](https://www.fortiguard.com/outbreak-alert/log4j2-vulnerability) outbreak report.

## Announced:
December 11, 2023: Cisco Talos posted a blog and shared the latest findings on [Lazarus New RATs DLang and Telegram](https://blog.talosintelligence.com/lazarus_new_rats_dlang_and_telegram)

Fortinet customers remain protected by the IPS signature `Apache.Log4j.Error.Log.Remote.Code.Execution` and the Antivirus detections for the related Remote Access Trojans(RATs).

## Latest Developments:
December 2023: According to the FortiGuard telemetry, there is significantly increased activity in the IPS detection of up to 65,000+ unique IPS devices. However, this particular campaign is just one of the instances where threat actors are still actively targeting the log4j vulnerability and using it as an initial access due to its widespread usage.

According to a report by Veracode, over 30% of Log4J apps still use a vulnerable version of the library even after 2 years of the patches being released. A log4j dashboard by Sonatype shows that 26% of the library’s downloads in the past week were concerning vulnerable versions [Log4j Vulnerability Resource Center](https://www.sonatype.com/resources/log4j-vulnerability-resource-center).

FortiGuard Labs recommends companies scan their environment, find the versions of open-source vulnerable libraries in use, develop an upgrade plan for them, and always follow best practices.

# Next Steps

| [Installation](./docs/setup.md#installation) | [Configuration](./docs/setup.md#configuration) | [Usage](./docs/usage.md) | [Contents](./docs/contents.md) |
|----------------------------------------------|------------------------------------------------|--------------------------|--------------------------------|