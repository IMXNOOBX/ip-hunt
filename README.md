# 🎱 ip-hunt

<div align="center">

<img src="https://img.shields.io/badge/iphunt-1.0.6-green.svg?style=flat&logo=github">

Did you ever heard "that's like looking for a needle in a haystack"? Well, this project plans to solve that. A simple minecraft server scanner that stores the data collected using quick.db 

<img height="250px" src="data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHN2ZyB3aWR0aD0iNzUycHQiIGhlaWdodD0iNzUycHQiIHZlcnNpb249IjEuMSIgdmlld0JveD0iMCAwIDc1MiA3NTIiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CiA8Zz4KICA8cGF0aCBkPSJtMzUxLjYzIDM3OC4xNy0xMC40NjEgMTAuNDY1IDIwLjAzMSAyMC4wMzEgNDUuOTMtNDUuOTMtMTAuNDY1LTEwLjQ2NS0zNS40NjUgMzUuNDY5eiIvPgogIDxwYXRoIGQ9Im0zMDkuNCAzNDEuODN2NjguMzQ0bDY2LjU5OCAzMy4yOTcgNjYuNTk4LTMzLjI5N3YtNjguMzQ0bC02Ni41OTgtMzMuMjk3em0xMTguNCA1OS4xOTktNTEuNzk3IDI1Ljg5OC01MS43OTctMjUuODk4di01MC4wNTFsNTEuNzk3LTI1Ljg5OCA1MS43OTcgMjUuODk4eiIvPgogIDxwYXRoIGQ9Im01OTguMzggMzU4LjE1LTUuNTcwMy02LjAwNzhjLTcuMDk3Ny03LjY0NDUtMTQuNTg2LTE0Ljg2Ny0yMi4zOTEtMjEuNjYgMTIuMzM2LTkuMzkwNiAyMC4xNzItMjUuNDUzIDIwLjE3Mi00My4yODFoLTE0LjgwMWMwIDE0LjYxMy02Ljc5MyAyNy41MTItMTcuMjAzIDMzLjUyLTguNDA2Mi02LjU3ODEtMTcuMTYtMTIuNjUyLTI2LjE4OC0xOC4yNyA4LjY0ODQtOS42NjAyIDEzLjc5My0yMy4xNjQgMTMuNzkzLTM3LjQ0NWgtMTQuODAxYzAgMTEuODI0LTQuNTM1MiAyMi44MzYtMTIuMDcgMjkuNzc3LTguNjY0MS00Ljc5NjktMTcuNTU5LTkuMTYwMi0yNi42NTItMTMuMDY2IDUuODc1LTguOTQ5MiA5LjEyNS0xOS45NjkgOS4xMjUtMzEuNTEyaC0xNC44MDFjMCA5LjgyMDMtMy4yMTA5IDE4Ljg5MS04LjY2NDEgMjUuNzg5LTkuODEyNS0zLjYxNzItMTkuODE2LTYuNzEwOS0yOS45NjktOS4yNzczIDUuNzkzLTguODkwNiA5LjAzNTItMTkuNzU0IDkuMDM1Mi0zMS4zMTJoLTE0LjgwMWMwIDEwLjY0OC0zLjc0NjEgMjAuNzU4LTEwLjExNyAyNy43NjYtOS4zNTk0LTEuODI4MS0xOC44MTYtMy4yNDIyLTI4LjM1NS00LjE2MDIgNS42NjQxLTguODI4MSA4Ljg3NS0xOS42MjUgOC44NzUtMzEuMDA0aC0xNC44MDFjMCAxMS45MzgtNC41NzQyIDIyLjg3MS0xMi4yNTQgMjkuODU5LTMuMzEyNS0wLjExMzI4LTYuNjIxMS0wLjI2MTcyLTkuOTQ1My0wLjI2MTcyLTIyLjU3OCAwLTQ0Ljg5NSAyLjY5OTItNjYuNTk4IDcuNzM4M3YtNC42NzU4bDE0LjgwMS0xNC44MDF2LTQwLjA1OWgtMTQuODAxdjMzLjkzNGwtMTQuODAxIDE0LjgwMXYxNC42NDVjLTQuOTgwNSAxLjQyOTctOS45MDYyIDIuOTg4My0xNC44MDEgNC42NzU4di0yNy45OTJsMTQuODAxLTE0LjgwMSAwLjAwMzkwNy00MC4wNjJoLTE0LjgwMXYzMy45MzRsLTE0LjgwMSAxNC44MDF2MzkuNjY0Yy00Ljk5NjEgMi4wMTk1LTkuOTIxOSA0LjE3OTctMTQuODAxIDYuNDY4OGwwLjAwMzkwNi0xMDkuNjZoLTE0LjgwMXYxMTcuMTJjLTUuMDA3OCAyLjY5OTItOS45NDUzIDUuNTI3My0xNC44MDEgOC41MTU2di01NC43MDdsLTE0LjgwMS0xNC44MDEgMC4wMDM5MDYtNDEuMzMyaC0xNC44MDF2NDcuNDYxbDE0LjgwMSAxNC44MDF2NTguMjY2Yy01LjA0NjkgMy41NDMtOS45Njg4IDcuMjczNC0xNC44MDEgMTEuMTM3di02MC43M2wtMTQuODAxLTE0LjgwMSAwLjAwMzkwNy0yNi41MzFoLTE0LjgwMXYzMi42NjRsMTQuODAxIDE0LjgwMXY2Ny4zMjRjLTUuODU5NCA1LjM1NTUtMTEuNTgyIDEwLjg5OC0xNy4wMiAxNi43NTRsLTUuNTY2NCA2Yy00LjUxOTUgNC44NjMzLTcuMDE1NiAxMS4yMDMtNy4wMTU2IDE3Ljg0OHMyLjQ5MjIgMTIuOTg4IDcuMDA3OCAxNy44NDhsNS41NzQyIDYuMDExN2M1NS43ODUgNjAuMDc4IDEzNC44MSA5NC41MzkgMjE2LjgxIDk0LjUzOSAyMi41NzggMCA0NC44OTUtMi42OTkyIDY2LjU5OC03LjczODN2NC42NzU4bC0xNC44MDEgMTQuODAxIDAuMDAzOTA2IDQwLjA1OWgxNC44MDF2LTMzLjkzNGwxNC44MDEtMTQuODAxdi0xNC42NDVjNC45ODA1LTEuNDI5NyA5LjkwNjItMi45ODgzIDE0LjgwMS00LjY3NTh2MjcuOTkybC0xNC44MDEgMTQuODAxLTAuMDAzOTA2IDQwLjA1OWgxNC44MDF2LTMzLjkzNGwxNC44MDEtMTQuODAxdi0zOS42NjRjNC45OTYxLTIuMDE5NSA5LjkyMTktNC4xNzk3IDE0LjgwMS02LjQ2ODhsLTAuMDAzOTA2IDEwOS42N2gxNC44MDF2LTExNy4xMmM1LjAwNzgtMi42OTkyIDkuOTQ1My01LjUyNzMgMTQuODAxLTguNTIzNHY1NC43MDdsMTQuODAxIDE0LjgwMS0wLjAwMzkwNyA0MS4zMzZoMTQuODAxdi00Ny40NjFsLTE0LjgwMS0xNC44MDF2LTU4LjI2NmM1LjA0NjktMy41NDMgOS45Njg4LTcuMjczNCAxNC44MDEtMTEuMTM3djYwLjczbDE0LjgwMSAxNC44MDEtMC4wMDM5MDYgMjYuNTM1aDE0LjgwMXYtMzIuNjY0bC0xNC44MDEtMTQuODAxdi02Ny4zMjRjNS44NTk0LTUuMzYzMyAxMS41OS0xMC44OTggMTcuMDI3LTE2Ljc2Mmw1LjU1ODYtNS45OTIyYzQuNTE5NS00Ljg2MzMgNy4wMTE3LTExLjIwNyA3LjAxMTctMTcuODUycy0yLjQ5MjItMTIuOTg0LTcuMDA3OC0xNy44NDh6bS0zMTguNTggMTcuODQ4YzAtNTMuMDQzIDQzLjE1Ni05Ni4xOTUgOTYuMTk1LTk2LjE5NSA1My4wNDMgMCA5Ni4xOTUgNDMuMTU2IDk2LjE5NSA5Ni4xOTUgMCA1My4wNDMtNDMuMTU2IDk2LjE5NS05Ni4xOTUgOTYuMTk1LTUzLjAzOSAwLjAwMzkwNy05Ni4xOTUtNDMuMTUyLTk2LjE5NS05Ni4xOTV6bS0xMDkuNzcgMTMuNzg1LTUuNTcwMy02LjAwNzhjLTEuOTc2Ni0yLjExMzMtMy4wNTg2LTQuODc1LTMuMDU4Ni03Ljc3NzNzMS4wODItNS42NjAyIDMuMDYyNS03Ljc5M2w1LjU2NjQtNi0wLjAwNzgxMiAwLjAwNzgxM2M0MS41NDMtNDQuNzM4IDk2LjY1Ni03NC40MjYgMTU2LjA1LTg1LjIxNS0zNi4xNzIgMTguMzI0LTYxLjA3IDU1Ljc2Ni02MS4wNyA5OSAwIDQzLjIzOCAyNC44OTggODAuNjggNjEuMDcgOTktNTkuMzkxLTEwLjc5My0xMTQuNS00MC40OC0xNTYuMDQtODUuMjE1em00MTcuNDktNS45OTIyLTUuNTU4NiA1Ljk5MjJjLTQxLjU0MyA0NC43MzgtOTYuNjU2IDc0LjQyNi0xNTYuMDUgODUuMjE1IDM2LjE3Mi0xOC4zMiA2MS4wNy01NS43NjIgNjEuMDctOTlzLTI0Ljg5OC04MC42ODgtNjEuMDctOTljNTkuMzgzIDEwLjc4OSAxMTQuNSA0MC40ODQgMTU2LjA0IDg1LjIwN2w1LjU3MDMgNi4wMDc4YzEuOTc2NiAyLjEyNSAzLjA1ODYgNC44ODY3IDMuMDU4NiA3Ljc4NTIgMCAyLjkwMjMtMS4wODIgNS42NjQxLTMuMDYyNSA3Ljc5M3oiLz4KICA8cGF0aCBkPSJtNTQ2LjIgNTc1Ljc5aDE0LjgwMXYxNC44MDFoLTE0LjgwMXoiLz4KICA8cGF0aCBkPSJtNTc1Ljc5IDU0Ni4yaDE0LjgwMXYxNC44MDFoLTE0LjgwMXoiLz4KICA8cGF0aCBkPSJtNDU3LjQgNTc1Ljc5aDE0LjgwMXYxNC44MDFoLTE0LjgwMXoiLz4KICA8cGF0aCBkPSJtNDI3LjggNTYwLjk5aDE0LjgwMXYxNC44MDFoLTE0LjgwMXoiLz4KICA8cGF0aCBkPSJtNTAxLjggNTkwLjU5aDE0LjgwMXYxNC44MDFoLTE0LjgwMXoiLz4KICA8cGF0aCBkPSJtMTkxLjAxIDE2MS40MWgxNC44MDF2MTQuODAxaC0xNC44MDF6Ii8+CiAgPHBhdGggZD0ibTE2MS40MSAxOTEuMDFoMTQuODAxdjE0LjgwMWgtMTQuODAxeiIvPgogIDxwYXRoIGQ9Im0yNzkuOCAxNjEuNDFoMTQuODAxdjE0LjgwMWgtMTQuODAxeiIvPgogIDxwYXRoIGQ9Im0zMDkuNCAxNzYuMjFoMTQuODAxdjE0LjgwMWgtMTQuODAxeiIvPgogIDxwYXRoIGQ9Im0yMzUuNDEgMTQ2LjYxaDE0LjgwMXYxNC44MDFoLTE0LjgwMXoiLz4KIDwvZz4KPC9zdmc+Cg==">

</div>

# 📣 Whats New

> 1.0.6 - Fork from [minescrap](https://github.com/GaspardCulis/minescrap) and some improvements for personal use<br>

## 🔺 Features

```diff
+ Working Features 
	• Minecraft Scanner - Using the moduel node-masscan a wrapper for masscan. 
	• Conbinient improvements - Some improvements that were useful for me.
- To Do
    • Nothing - As it is a simple fork and a simple program i dont have intended to put much more work into it.
```

## 🪁 Simple Use

***Install***

> apt install masscan<br>
> npm install

***Run***

> node index.js