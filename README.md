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

**Folder cis_dsi321_final**
* ไฟล์ main.py
* โฟลเดอร์ website
    - ไฟล์ init.py
          > ใช้ในการสร้าง Database User & Admin_user 
    - ไฟล์ auth.py
    - ไฟล์ models.py
    - ไฟล์ views.py
    - โฟลเดอร์ templates
        - add_com.html
        - add_job.html
        - base.html
        - base_staff.html
        - before_login.html
        - com_staff.html
        - company.html
        - error.html
        - home.html
        - home_staff.html
        - job1.html
        - job_staff.html
        - login.html
        - login_staff.html
        - sign_up.html
        - sign_up_staff.html
        - success.html
        - success_staff.html
    - database.db
        - table User
          > ตารางข้อมูลของนักศึกษา มี Attributes คือ Email, Student ID, Password
        - table Admin_User
          > ตารางข้อมูลของผู้ดูแลระบบ มี Attributes คือ Staff ID, Password
    - dbnew.db
        - Company
          > ตารางข้อมูลของบริษัท มี Attributes คือ Company_ID, Staff_ID, Company_Name, Company_Photo, Company_Type, Company_address, Company_Email, Contact_Number, Fax_Number, Established_Data, Company_Detail, Company_Link, Status
        - Job_Position
          > ตารางข้อมูลของตำแหน่งงาน มี Attributes คือ Job_Position_ID, Company_ID, Staff_ID, Job_Position_Name, Job_Amount_Required, Compensation, Job_Description, Position_Qualification, Working_Period, Application_Deadline, Job_Position_Link

**เว็บไซต์ที่ทำการ Deploy**


[projectdsi321](https://projectdsi321.herokuapp.com/)

**สมาชิกในกลุ่ม**
 1. นายวรท กาญจนาคม   เลขทะเบียนนักศึกษา 6209656070 
 2. นางสาวณัฐจิรา จมูศรี  เลขทะเบียนนักศึกษา 6209656112
 3. นางสาวปวีณ์ญา พุ่มวันเพ็ญ เลขทะเบียนนักศึกษา 6209656161
 4. นางสาวศุกลภัทร ชิณวงศ์ เลขทะเบียนนักศึกษา 6209656203
 5. นางสาววิมลฉัตร อาภาสุขเจริญ เลขทะเบียนนักศึกษา 6209656344
 6. นางสาวญาณิศา สมจันทร์ เลขทะเบียนนักศึกษา 6209656385
 7. นางสาวชนัญญา เพชรน้อย เลขทะเบียนนักศึกษา 6209656401
 8. นางสาวพิมพ์ชนก ชื่นชม เลขทะเบียนนักศึกษา 6209656500
