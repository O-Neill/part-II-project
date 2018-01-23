call ant -buildfile ant_tasks\build_opacity.xml

GPShell.exe gpshellscripts\opacityinstall.txt

python ..\code\Python\HostApp\Issuer.py

python ..\code\Python\HostApp\HostApp.py