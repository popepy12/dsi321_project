# CIS - Cooperation Education Management System
  
  **สหกิจศึกษา** คือ การศึกษาที่เน้นให้นักศึกษาได้ใช้ความรู้ที่เรียนมาไปประยุกต์ใช้กับการทำงานจริง ซึ่งเรียกว่าสถานประกอบการหรือองค์กรผู้ใช้บัณฑิตอย่างเป็นระบบก่อนการสำเร็จการศึกษา โดยที่ทางวิทยาลัยสหวิทยาการ มหาวิทยาลัยธรรมศาสตร์ จะต้องให้นักศึกษาได้ไปใช้เวลาอยู่ในสถานประกอบการเป็นระยะเวลาอย่างน้อย 1 ภาคการศึกษา หรือ 4 เดือน เนื่องจากนักศึกษาที่ไปทำสหกิจศึกษานั้นจะอยู่ในฐานะเดียวกับพนักงานของสถานประกอบการ จึงต้องมีขั้นตอนการสมัครและคัดเลือกเหมือนสมัครงานจริง และสถานประกอบการนั้นจะต้องมีความพร้อมในการรับนักศึกษาไปทำสหกิจศึกษาด้วย
  
  ที่ผ่านมาการดำเนินงานจัดการสหกิจศึกษาจะกระทำโดยอาจารย์และเจ้าหน้าที่ผู้รับผิดชอบ ประสานงานกับสถานประกอบการทีละแห่ง ต้องจัดการกับเอกสารจำนวนมาก ทำให้เกิดความล่าช้า นอกจากนี้ นักศึกษาก็จำเป็นที่จะต้องหาสถานประกอบการที่เปิดรับสมัครในช่วงเวลานั้น ๆ ด้วยตัวเอง และยังไม่สามารถสืบค้นข้อมูลของสถานประกอบการได้จากทางวิทยาลัยสหวิทยาการ มหาวิทยาลัยธรรมศาสตร์อีกด้วย ทำให้นักศึกษาไม่เห็นภาพรวมของสถานประกอบการทั้งหมดที่เข้าร่วมสหกิจศึกษา
  
  นอกจากในส่วนของนักศึกษาแล้ว อาจารย์ที่มีหน้าที่ดูแลนักศึกษาในการทำสหกิจศึกษานั้นจะต้องผ่านการอบรมคณาจารย์นิเทศและได้รับวุฒิบัตรก่อน ถึงจะทำหน้าที่อาจารย์นิเทศสหกิจศึกษาได้ ซึ่งข้อมูลเกี่ยวกับการอบรมนั้นมีการกระจายอยู่ในเว็บไซต์หลายที่ ทำให้สืบค้นได้ยาก จึงส่งผลให้เสียโอกาสในการเข้าอบรมได้ทันเวลา
  
  **ดังนั้น** ทางกลุ่มจึงได้จัดทำระบบ CIS Cooperative Education Management เพื่อช่วยให้นักศึกษา อาจารย์ และเจ้าหน้าที่ สามารถเข้าถึงข้อมูลในการสืบค้น หรือการจัดการข้อมูลที่เกี่ยวกับสหกิจศึกษาได้สะดวก รวดเร็ว และเห็นภาพรวมได้มากขึ้น 
  ในระบบนี้ทางกลุ่มได้จัดทำระบบ CIS Cooperative Management ใน 2 ผู้ใช้งาน ดังนี้
  
  **1) ในส่วนของนักศึกษา (User Student)**
- การเข้าสู่ระบบ (Log-in)
- หน้าหลักหลังจากการเข้าสู่ระบบ (Home)
- การค้นหาสถานประกอบการ (Company) 
- รายละเอียดของงาน (Job Description) 

**2) ในส่วนของเจ้าหน้าที่ (User Staff / Admin)**
- การเข้าสู่ระบบ (Log-in)
- หน้าหลักหลังจากการเข้าสู่ระบบ (Home)
- จัดการกับข้อมูลของนักศึกษา (Sign-up / Add Students) 
- การจัดการสถานประกอบการในการเพิ่ม แก้ไข และลบข้อมูลของสถานประกอบการ (Add, Edit and Delete Company)
- การจัดการรายละเอียดงานของสถานประกอบการในการเพิ่ม แก้ไข และลบข้อมูลของสถานประกอบการ (Add, Edit and Delete Job Description)

**การติดตั้ง**

pip install -r requirements.txt 


**ขั้นตอนการ Deploy**

1. Download และ Install Heroku
2. Login เข้าสู่ระบบของ Heroku ใน command line โดยใช้คำสั่ง 
    
    heroku login
    
4. ทำการ Clone โปรเจคที่เราจะ Deploy จากใน Local Machine โดยใช้คำสั่ง
 
    heroku git:clone -a {ชื่อโปรเจคที่เรามีภายในเครื่อง}
    
6. ทำการเรียกใช้โปรเจคนั้น โดยใช้คำสั่ง

    cd {ชื่อโปรเจคที่เรามีภายในเครื่อง}
    
8. ทำการแก้ไข code ที่เรา Clone เข้ามา เพื่อให้สามารถ Deploy ใน Heroku ได้
9. ทำการ Deploy ใน Heroku โดยใช้ Git โดยใช้คำสั่ง
 
    git add .
    
    git commit -am "make it better"
    
    git push heroku master

**เว็บไซต์ที่ทำการ Deploy**


[Project_DSI321_Website](https://projectdsi321.herokuapp.com/)

**สมาชิกในกลุ่ม**
 1. นายวรท กาญจนาคม   เลขทะเบียนนักศึกษา 6209656070 
 2. นางสาวณัฐจิรา จมูศรี  เลขทะเบียนนักศึกษา 6209656112
 3. นางสาวปวีณ์ญา พุ่มวันเพ็ญ เลขทะเบียนนักศึกษา 6209656161
 4. นางสาวศุกลภัทร ชิณวงศ์ เลขทะเบียนนักศึกษา 6209656203
 5. นางสาววิมลฉัตร อาภาสุขเจริญ เลขทะเบียนนักศึกษา 6209656344
 6. นางสาวญาณิศา สมจันทร์ เลขทะเบียนนักศึกษา 6209656385
 7. นางสาวชนัญญา เพชรน้อย เลขทะเบียนนักศึกษา 6209656401
 8. นางสาวพิมพ์ชนก ชื่นชม เลขทะเบียนนักศึกษา 6209656500
