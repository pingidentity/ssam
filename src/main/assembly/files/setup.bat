@echo off
rem Copyright 2016-2018 Ping Identity Corporation
rem
rem Executes the Self-Service Account Manager application installer.  Run the
rem script without any arguments to display the help, and refer to the
rem documentation for additional information.
rem

rem Go into the script directory and export the SCRIPT_DIR, which is required by
rem the installer.
setlocal

rem check that the path does not contain the ^% character which breaks
rem the batch files.
for %%i in (%~sf0) do set NON_ESCAPED=%%~dPsi..

for /F "tokens=1-2* delims=%%" %%1 IN ("%NON_ESCAPED%") DO (
if NOT "%%2" == "" goto invalidPath)

for %%i in (%~sf0) do set SCRIPT_DIR=%%~dPsi.

rem Make sure the war file is in the same directory as the script, and make sure
rem that java is in the PATH.
if not exist "%SCRIPT_DIR%\ssam.war" goto noWar

rem Check for Java binary
if "%JAVA_HOME%" == "" goto noJavaFound
if not exist "%JAVA_HOME%\bin\java.exe" goto checkJavaBin

rem Run the installer or display the help if no arguments were provided.
if "%1" == "" goto usage
"%JAVA_HOME%\bin\java.exe" -jar "%SCRIPT_DIR%\ssam.war" install %*

:success
exit /b 0

:usage
"%JAVA_HOME%\bin\java.exe" -jar "%SCRIPT_DIR%\ssam.war" install --help
exit /b 0

:noWar
echo The ssam.war file must exist in %SCRIPT_DIR%
exit /b 1

:noJavaFoundSetup
echo ERROR:  Could not find a valid java binary to be used.
echo Please set JAVA_HOME to the root of a supported Java installation.
exit /b 1

:checkJavaBin
echo Make sure that java is in the PATH.
exit /b 1

:invalidPath
echo Error: The current path contains a %% character. Cannot install
echo        in a path containing this character.
exit /b 1
