# Port

Port is a layered detection agent, that sits on the network interface and identifies port scanning behaviour in real time. 

``` 
Port Scanning is a form of techinque used to probe a device or network to determine which ports are closed, open or filtered. Malicious attackers use this technique as a form of reconnaissance, checking for doors are open which they can exploit. 
```

Port, as a triage agent, can deduce if any reconnaisaance has occured or any scans has occured at a given time, using LLMs and other tools like Zeek, Suricata and libpcap. 
(Note: this agent is not a live product as of yet.)

## Architecture 
```
    -----------------          -----------------        -----------------       -----------------       -----------------
    |    Traffic    |          |    Traffic    |        |   Signature   |       |    Triage     |       |               |
    |    Capture    | -------> |    History/   | ------>|   Detection   |------>|    Agent      |------>|    Result     |
    |      (1)      |          |     Logs (2)  |        |     (3)       |       |     (4)       |       |     (5)       |
    -----------------          -----------------        -----------------       -----------------       -----------------
```
   
**(1) Traffice Capture - libpcap** 
It captures the raw data of the packet - source and destination IP addresses and ports, payload, protocol, flags, timestamps, etc. 
This creates the foundation for which the tools will work on. 

**(2) Traffic History/Logs - Zeek** 
Parses the packets into structured connection logs, who connected to what, when, how and for how long. Zeek shows the logs of all the connections made, as well patterns. Mainly useful when suricata does not recognize it to be a scan (due to larger gaps), providing behavioural context, distributed scan detection, and slow scan detection. 

**(3) Signature Detection - Suricata** 
Port scanners usually operate with the help of scan patterns, like SYN, FIN, NULL, XMAS, UDP scans. Suricata helps in identifying the pattern the ports have been scanned with. 

**(4) Triage Agent - ollama + ip reputation lookup** 
False Positive Filtering, using pattern correlation, scan type classification and attacker profiling. 
Understands alert, and provides context, priority, or recommended action

**(5) Result - Incident Report** 
Generates a report based on the 4 pillars above. 



    
            


















A layered detection agent that sits on the network interface and identifies port scanning behaviour in real time. Incoming traffic is captured via libpcap, parsed into structured connection logs by Zeek, and matched against known scan signatures by Suricata. A local LLM (triage agent) then cross-references flagged activity against the CVE database via RAG — using IP reputation lookup and CVE intent classification as the four pillars of a final verdict. Novel or evasion-based scan patterns that defeat signature matching are escalated to a frontier reasoning model for deeper analysis. The full stack is designed to be cost-efficient, with expensive model calls gated behind local filtering that handles the majority of decisions for free.

