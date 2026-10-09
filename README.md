# ExtremeSee


🇺🇸
What is ExtremeSee?

ExtremeSee is a kernel driver program coded for malware analysis.

How does it work?

**For example, when any application is launched, it starts with certain parameters—such as "powershell.exe -windowstyle hidden"—which Windows does not show.**
**While Process Monitor can detect this easily because it loads into memory but easily detected because loading memory, but this method is cleaner and carries a lower risk of detection.**
**When the driver starts, it creates a log file named C:\ExtremeSee.log, and since it is a kernel driver, it monitors every application. For example, if you load a ****virus:**
**The virus creates a hidden process called "powershell.exe -WindowStyle Hidden" that you cannot see, and the ExtremeSee driver detects and logs it for you.**
**The logs look like this:**
**[Date] [Process Created] powershell.exe -WindowStyle Hidden**
**It displays these to you, and because it is open source, it is open to development. We ensure that it will receive continuous updates.**

How to run driver?

**Copy driver file C:\windows\system32\drivers\ExtremeSee.sys**
**And open a cmd run it adminastrator and type that:**
```sc create ExtremeSee binPath= "C:\windows\system32\drivers\ExtremeSee.sys" type= kernel start= demand```
**When you type that, type cmd "sc start extremesee" driver should open and writes log tho c:\extremesee.log**
**You need sign driver or close driver sig enforcement for driver run.**

🇹🇷
ExtremeSee nedir?

**ExtremeSee virüslü dosya analizi için kodlanmış bir kernel driver programıdır.**

Nasıl çalışır?

**Örneğin her bir uygulama başlatıldığında belirli paragraflarla başlıyor örneğin: "powershell.exe -windowstyle hidden" Windows bunu göstermiyor,**
**Process Monitor ise belleğe yüklendiği için kolayca tespit edilebiliyor bu yöntem hem daha güzel ve tespit edilme riski daha azdır.**
**Driver başlatıldığında C:\ExtremeSee.log diye bir log dosyası oluşturur ve her uygulamyi kernel driver olduğu için izler ve örneğin bir virüs yüklediniz:**
**Virüs "powershell.exe -WindowStyle Hidden" adlı bir uygulama oluşturdu ve siz bunu göremiyorsunuz ve ExtremeSee dirveri sizin için bunu algılar ve loglar**
**Loglar şu şekildedir:**
**[Tarih] [Process Created] powershell.exe -WindowStyle Hidden**
**Bunları size gösterir ve açık kaynak olduğu için geliştirilmeye açık bir programdır, sürekli güncellemeler alıcağını temin ederiz.**

Driver nasıl çalıştırılır?

C:\windows\system32\drivers\ExtremeSee.sys sürücü dosyasını kopyalayın.

Ve yönetici olarak bir CMD (Komut İstemi) açıp şunu yazın:
```sc create ExtremeSee binPath= "C:\windows\system32\drivers\ExtremeSee.sys" type= kernel start= demand```
Bunu yazdıktan sonra CMD'ye sc start extremesee komutunu girin; sürücü açılmalı ve c:\extremesee.log dosyasına log yazmaya başlamalıdır.

Sürücünün çalışabilmesi için ya sürücüyü imzalamanız ya da sürücü imza zorlamasını (driver signature enforcement) kapatmanız gerekir.

