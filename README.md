# rproxifier
一个rust编写的类似Proxifier全局TCP路由的流量转发软件

### 工作原理
macos使用了tun + fakeIp 的方式实现（master分支）
windows使用了两种方式实现，1. wintun + fakeIp (master分支)；2. windivert流量过滤方式实现（windows分支）

### 截图展示
gui为![rproxifier-gui（Java Swing）项目](!https://github.com/villcore/rproxifier-gui)，使用http调用数据接口

![图片](https://user-images.githubusercontent.com/11493797/166619084-ba456efa-5ad4-4aba-ab99-2d55edd159dd.png)
![process](https://user-images.githubusercontent.com/11493797/166620285-7aa3c4e7-05d1-4f01-80a2-27216fcd8d62.PNG)
![connectoin](https://user-images.githubusercontent.com/11493797/166620290-97130744-54a4-4070-9352-3eaf39790da7.PNG)
![proxy](https://user-images.githubusercontent.com/11493797/166620297-a17858e0-8c33-41eb-a309-f2f1d099c704.PNG)
![rule](https://user-images.githubusercontent.com/11493797/166620299-bf9189dc-5121-4061-8723-e50eb04eb663.PNG)
