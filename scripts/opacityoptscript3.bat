call ant -buildfile ant_tasks\build_opacity_opt.xml

GPShell.exe gpshellscripts\opacityoptinstall.txt

python ..\code\Python\HostAppOpt\Issuer.py

python ..\code\Python\HostAppOpt\HostApp.py