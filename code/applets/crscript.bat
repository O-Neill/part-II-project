
javac -g -source 1.5 -target 1.5 -cp ".\bin;..\..\..\java_card_jdk\2.2.2\java_card_kit-2_2_2\lib\api.jar;..\..\..\java_card_jdk\2.2.2\java_card_kit-2_2_2\lib\installer.jar" -d .\bin src/uk/ac/cam/bo271/applets/challengeresponse/ChallengeResponse.java
call converter -exportpath "..\..\..\java_card_jdk\2.2.2\java_card_kit-2_2_2\api_export_files" -classdir .\bin -applet 0xD1:0xD2:0xD3:0xD4:0xD5:0xD6:0x01 uk.ac.cam.bo271.applets.challengeresponse.ChallengeResponse uk.ac.cam.bo271.applets.challengeresponse 0xD1:0xD2:0xD3:0xD4:0xD5:0xD6 1.0

GPShell.exe gpshellscripts\crinstall.txt

py ..\Python\challengeresponsehost\ChallengeResponse.py

