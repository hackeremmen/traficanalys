# traficanalys
Traffic analysis I Tawt I Taw A C2 Tat!



										TryHackme - Advent of Cyber 2023 | Traffic analysis I Tawt I Taw A C2 Tat!
										==========================================================================


Which version of SiLK is installed on the VM?
ubuntu@ip-10-10-54-183:~/Desktop$ silk_config -v
silk_config: part of SiLK 3.19.1; configuration settings:
    * Root of packed data tree:         /var/silk/data
    * Packing logic:                    Run-time plug-in
    * Timezone support:                 UTC
    * Available compression methods:    lzo1x [default], none, zlib
    * IPv6 network connections:         yes
    * IPv6 flow record support:         yes
    * IPset record compatibility:       3.14.0
    * IPFIX/NetFlow9/sFlow collection:  ipfix,netflow9,sflow
    * Transport encryption:             GnuTLS
    * PySiLK support:                   /usr/local/lib/python2.7/site-packages
    * Enable assert():                  no
Copyright (C) 2001-2020 by Carnegie Mellon University
GNU General Public License (GPL) Rights pursuant to Version 2, June 1991.
Some included library code covered by LGPL 2.1; see source for details.
Government Purpose License Rights (GPLR) pursuant to DFARS 252.227-7013.
Send bug reports, feature requests, and comments to netsa-help@cert.org.
ubuntu@ip-10-10-54-183:~/Desktop$ rwfileinfo suspicious-flows.silk
suspicious-flows.silk:
  format(id)          FT_RWIPV6ROUTING(0x0c)
  version             16
  byte-order          littleEndian
  compression(id)     lzo1x(2)
  header-length       88
  record-length       88
  record-version      1
  silk-version        3.19.1
  count-records       11774
  file-size           152366
  command-lines       
                   1  rwipfix2silk --silk-output=test.silk
Answer: 3.19.1

What is the size of the flows in the count records?
ubuntu@ip-10-10-54-183:~/Desktop$ rwfileinfo suspicious-flows.silk
suspicious-flows.silk:
  format(id)          FT_RWIPV6ROUTING(0x0c)
  version             16
  byte-order          littleEndian
  compression(id)     lzo1x(2)
  header-length       88
  record-length       88
  record-version      1
  silk-version        3.19.1
  count-records       11774
  file-size           152366
  command-lines       
                   1  rwipfix2silk --silk-output=test.silk
Answer: 11774


What is the start time (sTime) of the sixth record in the file?
ubuntu@ip-10-10-54-183:~/Desktop$ rwcut suspicious-flows.silk --num-recs=5
                                    sIP|                                    dIP|sPort|dPort|pro|   packets|     bytes|   flags|                  sTime| duration|                  eTime|sen|
                        175.215.235.223|                        175.215.236.223|   80| 3222|  6|         1|        44| S  A   |2023/12/05T09:33:07.719|    0.000|2023/12/05T09:33:07.719| S0|
                        175.215.235.223|                        175.215.236.223|   80| 3220|  6|         1|        44| S  A   |2023/12/05T09:33:07.725|    0.000|2023/12/05T09:33:07.725| S0|
                        175.215.235.223|                        175.215.236.223|   80| 3219|  6|         1|        44| S  A   |2023/12/05T09:33:07.738|    0.000|2023/12/05T09:33:07.738| S0|
                        175.215.235.223|                        175.215.236.223|   80| 3218|  6|         1|        44| S  A   |2023/12/05T09:33:07.741|    0.000|2023/12/05T09:33:07.741| S0|
                        175.215.235.223|                        175.215.236.223|   80| 3221|  6|         1|        44| S  A   |2023/12/05T09:33:07.743|    0.000|2023/12/05T09:33:07.743| S0|
ubuntu@ip-10-10-54-183:~/Desktop$ rwcut suspicious-flows.silk --num-recs=6
                                    sIP|                                    dIP|sPort|dPort|pro|   packets|     bytes|   flags|                  sTime| duration|                  eTime|sen|
                        175.215.235.223|                        175.215.236.223|   80| 3222|  6|         1|        44| S  A   |2023/12/05T09:33:07.719|    0.000|2023/12/05T09:33:07.719| S0|
                        175.215.235.223|                        175.215.236.223|   80| 3220|  6|         1|        44| S  A   |2023/12/05T09:33:07.725|    0.000|2023/12/05T09:33:07.725| S0|
                        175.215.235.223|                        175.215.236.223|   80| 3219|  6|         1|        44| S  A   |2023/12/05T09:33:07.738|    0.000|2023/12/05T09:33:07.738| S0|
                        175.215.235.223|                        175.215.236.223|   80| 3218|  6|         1|        44| S  A   |2023/12/05T09:33:07.741|    0.000|2023/12/05T09:33:07.741| S0|
                        175.215.235.223|                        175.215.236.223|   80| 3221|  6|         1|        44| S  A   |2023/12/05T09:33:07.743|    0.000|2023/12/05T09:33:07.743| S0|
                        175.215.235.223|                        175.215.236.223|   80| 3225|  6|         1|        44| S  A   |2023/12/05T09:33:07.755|    0.000|2023/12/05T09:33:07.755| S0|
Answer: 2023/12/05T09:33:07.755


What is the destination port of the sixth UDP record?
ubuntu@ip-10-10-54-183:~/Desktop$ rwcut suspicious-flows.silk --fields=protocol,sIP,sPort,dIP,dPort --num-recs=6
pro|                                    sIP|sPort|                                    dIP|dPort|
  6|                        175.215.235.223|   80|                        175.215.236.223| 3222|
  6|                        175.215.235.223|   80|                        175.215.236.223| 3220|
  6|                        175.215.235.223|   80|                        175.215.236.223| 3219|
  6|                        175.215.235.223|   80|                        175.215.236.223| 3218|
  6|                        175.215.235.223|   80|                        175.215.236.223| 3221|
  6|                        175.215.235.223|   80|                        175.215.236.223| 3225|
ubuntu@ip-10-10-54-183:~/Desktop$ rwfilter suspicious-flows.silk --proto=17 --pass=stdout | rwcut --num-recs=6
                                    sIP|                                    dIP|sPort|dPort|pro|   packets|     bytes|   flags|                  sTime| duration|                  eTime|sen|
                        175.175.173.221|                        175.219.238.243|59580|   53| 17|         1|       108|        |2023/12/08T04:28:44.825|    0.855|2023/12/08T04:28:45.680| S0|Answer: 
                        175.219.238.243|                        175.175.173.221|   53|59580| 17|         1|       203|        |2023/12/08T04:28:45.680|    0.000|2023/12/08T04:28:45.680| S0|
                        175.175.173.221|                        175.219.238.243|47888|   53| 17|         1|       108|        |2023/12/08T04:28:45.678|    0.158|2023/12/08T04:28:45.836| S0|
                        175.219.238.243|                        175.175.173.221|   53|47888| 17|         1|       203|        |2023/12/08T04:28:45.836|    0.000|2023/12/08T04:28:45.836| S0|
                        175.175.173.221|                        175.219.238.243|49950|   53| 17|         1|       108|        |2023/12/08T04:28:45.833|    0.053|2023/12/08T04:28:45.886| S0|
                        175.219.238.243|                        175.175.173.221|   53|49950| 17|         1|       157|        |2023/12/08T04:28:45.886|    0.000|2023/12/08T04:28:45.886| S0|
Answer: 49950


What is the record value (%) of the dport 53?
ubuntu@ip-10-10-54-183:~/Desktop$ rwstats suspicious-flows.silk --fields=dPort --values=records,packets,bytes,sIP-Distinct,dIP-Distinct --count=10
INPUT: 11774 Records for 5713 Bins and 11774 Total Records
OUTPUT: Top 10 Bins by Records
dPort|   Records|        Packets|               Bytes|        sIP-Distinct|        dIP-Distinct|  %Records|   cumul_%|
   53|      4160|           4333|              460579|                   1|                   1| 35.332088| 35.332088|
   80|      1658|           1658|               66320|                   1|                   1| 14.081875| 49.413963|
40557|         4|              4|                 720|                   1|                   1|  0.033973| 49.447936|
53176|         3|              3|                 465|                   1|                   1|  0.025480| 49.473416|
50088|         3|              3|                 517|                   1|                   1|  0.025480| 49.498896|
50258|         3|              3|                 517|                   1|                   1|  0.025480| 49.524376|
52345|         3|              3|                 513|                   1|                   1|  0.025480| 49.549856|
47920|         3|              3|                 515|                   1|                   1|  0.025480| 49.575335|
50105|         3|              3|                 563|                   1|                   1|  0.025480| 49.600815|
52167|         3|              3|                 561|                   1|                   1|  0.025480| 49.626295|
Answer: 35.332088


What is the number of bytes transmitted by the top talker on the network?
ubuntu@ip-10-10-54-183:~/Desktop$ rwstats suspicious-flows.silk --fields=sIP --values=bytes --count 10 --top
INPUT: 11774 Records for 8 Bins and 1412597 Total Bytes
OUTPUT: Top 10 Bins by Bytes
                                    sIP|               Bytes|    %Bytes|   cumul_%|
                        175.219.238.243|              735229| 52.048036| 52.048036|
                        175.175.173.221|              460731| 32.615884| 84.663920|
                        175.215.235.223|              145948| 10.331892| 94.995813|
                        175.215.236.223|               66320|  4.694899| 99.690712|
                         181.209.166.99|                2744|  0.194252| 99.884964|
                         253.254.236.39|                1380|  0.097692| 99.982656|
                         205.213.108.99|                 152|  0.010760| 99.993416|
87d6:ebe3:bdd7:ece3:7dfb:3cb0:83b7:a4fa|                  93|  0.006584|100.000000|
Answer: 735229


What is the sTime value of the first DNS record going to port 53?

ubuntu@ip-10-10-54-183:~/Desktop$ rwfilter suspicious-flows.silk --saddress=175.175.173.221 --dport=53 --pass=stdout | rwcut --fields=sIP,dIP,stime,dport | head -10
                                    sIP|                                    dIP|                  sTime|dPort|
                        175.175.173.221|                        175.219.238.243|2023/12/08T04:28:44.825|   53|
                        175.175.173.221|                        175.219.238.243|2023/12/08T04:28:45.678|   53|
                        175.175.173.221|                        175.219.238.243|2023/12/08T04:28:45.833|   53|
                        175.175.173.221|                        175.219.238.243|2023/12/08T04:28:46.743|   53|
                        175.175.173.221|                        175.219.238.243|2023/12/08T04:28:46.898|   53|
                        175.175.173.221|                        175.219.238.243|2023/12/08T04:28:47.753|   53|
                        175.175.173.221|                        175.219.238.243|2023/12/08T04:28:47.903|   53|
                        175.175.173.221|                        175.219.238.243|2023/12/08T04:28:48.764|   53|
                        175.175.173.221|                        175.219.238.243|2023/12/08T04:28:48.967|   53|
Answer: 2023/12/08T04:28:44.825

What is the IP address of the host that the C2 potentially controls? (In defanged format: 123[.]456[.]789[.]0 )
Answer: 175[.]175[.]173[.]221


Which IP address is suspected to be the flood attacker? (In defanged format: 123[.]456[.]789[.]0 )
Answer: 175[.]215[.]236[.]223


What is the sent SYN packet's number of records?
ubuntu@ip-10-10-54-183:~/Desktop$ rwfilter suspicious-flows.silk --saddress=175.215.236.223 --pass=stdout | rwstats --fields=sIP,dIP,flag --count 10
INPUT: 1658 Records for 1 Bin and 1658 Total Records
OUTPUT: Top 10 Bins by Records
                                    sIP|                                    dIP|   flags|   Records|  %Records|   cumul_%|
                        175.215.236.223|                        175.215.235.223| S      |      1658|100.000000|100.000000|
Answer: 1658


