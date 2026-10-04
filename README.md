# ExtremeSee


🇺🇸
What is ExtremeSee?

ExtremeSee is a kernel driver program coded for infected file analysis.

How does it work?

**For example, when any application is launched, it starts with certain parameters—such as "powershell.exe -windowstyle hidden"—which Windows does not show.**
**While Process Monitor can detect this easily because it loads into memory, this method is cleaner and carries a lower risk of detection.**
**When the driver starts, it creates a log file named C:\ExtremeSee.log, and since it is a kernel driver, it monitors every application. For example, if you load a ****virus:**
**The virus creates a hidden process called "powershell.exe -WindowStyle Hidden" that you cannot see, and the ExtremeSee driver detects and logs it for you.**
**The logs look like this:**
**[Date] [Process Created] powershell.exe -WindowStyle Hidden**
**It displays these to you, and because it is open source, it is open to development. We ensure that it will receive continuous updates.**


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
