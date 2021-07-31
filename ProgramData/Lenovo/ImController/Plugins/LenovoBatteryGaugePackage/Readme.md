========================================================================
[Notice]:
Please include all the following files whenever you use or deliver 
LenovoBatteryGaugePackage:
1) this Readme.txt
2) LenovoBatteryGaugePackage_ThirdPartyNOTICEs.txt
3) all open source licenses included in this LenovoBatteryGaugePackage.
========================================================================


========================================================================
About LenovoBatteryGaugePackage
========================================================================
1, Introduction
2, Solution directory hierarchy
3, How to use
4, Release notes

////////////////////////////////////////////////////////////////////////

1, Introduction
LenovoBatteryGaugePackage is a set of Windows applications(.exe) and  
extensions(.dll), which provide some settings of system and as quick 
settings of Lenovo Vantage UAP.

It contains the following modules:
1) BatteryGauge
	It's a deskband object which displays basic battery & charging
	info, and also the quick entry of QuickSetting/QuickSettingEx.
	
2) QuickSetting
	A quick settings panel of Lenovo Vantage UAP 2.x & LESetting 2.x series.
	
3) QuickSettingEx
	A quick settings panel of Lenovo Vantage UAP 3.x series.
	
4) Accessories
	As you can see in "2, Solution directory hierarchy", the package contains
	several other Apps & DLLs, while all these modules re accessories of 
	BatteryGauge, QuickSetting and 	QuickSettingEx. Such as Duilib is UI 
	library used in QuickSetting.exe, while ShowBatteryLowToastNotification.exe 
	is used by BatteryGauge to pop up a toast message.
	

////////////////////////////////////////////////////////////////////////

2, Solution directory hierarchy
The following is framework of LenovoBatteryGaugePackage solutoin.

LenovoBatteryGaugePackage
©¦  LenovoBatteryGaugePackage_ThirdPartyNOTICEs.txt
©¦  Readme.txt
©¦  
©À©¤BatteryGauge
©¦  ©¦  
©¦  ©¸©¤data
©¦      ©¦  
©¦      ©¸©¤Licenses
©¦              directui license.txt
©¦              duilib license.txt
©¦              Info-ZIP license.txt
©¦              Newtonsoft.Json LICENSE.md
©¦              System.IdentityModel.Tokens.Jwt license.txt
©¦              tinyxml LICENSE.txt
©¦              zlib license.txt
©¦              
©À©¤BGHelper
©À©¤DuiLib     
©À©¤HeartbeatMetrics
©À©¤IdeaIntelligentCoolingMetrics
©À©¤PinVantageToolbarToast
©À©¤PluginsContract
©À©¤PluginSeeker
©À©¤QuickSetting
©¦  ©¦      
©¦  ©¸©¤tinyxml
©À©¤QuickSettingEx
©¦  ©¦      
©¦  ©¸©¤tinyxml
©À©¤SetThinkTouchPad
©¸©¤ShowBatteryLowToastNotification



////////////////////////////////////////////////////////////////////////

3, How to use
You can use LenovoBatteryGaugePackage after install Lenovo Vantage from 
Microsoft Store. The following steps might be helpful.
1) Search and install Lenovo Vantage from Microsoft Store.
2) Pin "Lenovo Vantage Toolbar" from taskbar right-click menu (or from 
Lenovo Vantage Power Page), then you will see BatteryGauge icon is pinned
on taskbar.
3) We can get battery percentage & remaining time from BatteryGauge icon
just by a glance, and can also launch QuickSetting/QuickSettingEx by
clicking the icon.
4) Through QuickSetting/QuickSettingEx, we can change some device settings,
such as turn on/off Microphone, Camera, ConservationMode, RapidCharge,
switch Keyboard Backlight, Top-row key function, Intelligent Cooling, etc.


////////////////////////////////////////////////////////////////////////

4, Release notes
1) Currently, LenovoBatteryGaugePackage only supports Win10 OS.
2) The first version released at 2015.
3) v1.0.113.18 released at 2019-4-27. 
	QuickSettingEx was completed in this version to support Lenovo Vantage 3.x.
4) v1.1.1.94 released at 2020-9-22.
