# GNChecker

GNChecker is a compliance checking tool with low false negatives and finer granularity.  This tool is divided into three main components: program behavior analysis, privacy policy analysis, and consistency analysis. In the program behavior analysis, we employ both static data flow analysis and dynamic network traffic analysis to identify which types of information will be sent to where, and these data transmission behaviors are mapped to IT-TA (Information Type, Transmission Address) tuples. For privacy policy analysis, we map the declared privacy policies to tuples of DCP-IT to represent which data collection party will collect what information. Finally, during the consistency analysis phase, we utilize pre-constructed dictionaries for DCPs and types of information to expand the aforementioned tuples into triples of DCP-IT-TA . And then through a process of consistency comparison, we identify inconsistencies.

# Experimental setup

1. Java version 1.8 or above, Python version 3.7 or above, install relevant third-party libraries
2. Please download Android SDK from the  address [https://android-sdk.en.softonic.com/download]()
3. This article uses the Night God Simulator. For download details, please refer to [https://www.yeshen.com/](https://www.yeshen.com/)
4. This article uses the fastboot dynamic testing tool. For details on Android, please refer to [https://github.com/bytedance/Fastbot_Android.git](https://github.com/bytedance/Fastbot_Android.git)

# Static Analysis

The relevant input files can be found in static_analysis/input

Run command：

```
java -cp GNChecker_Static_Analysis.jar datashare.DataShare apk_path source sink source_and_sink regex easytaintsource sdk_platforms callbacks python_home cg_process.py
```

# Dynamic Analysis

Just fill in the information in dynamic_test.py

# PP Analysis

Apply for gpt API permissions and complete the relevant information in pp_gpt.py

