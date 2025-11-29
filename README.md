# 🎫 GateMate – Smart Gate Pass Management System

GateMate is a modern **Flask-based Gate Pass Management System** designed for colleges.  
It includes **OTP verification**, **QR-based gate pass validation**, **HOD approval**, and **Twilio SMS alerts**.

---

## 🚀 Features

### 👨‍🎓 Student Features
- Submit gate pass request  
- OTP verification sent to parent’s mobile  
- View request history  
- Auto-generated QR code for approved requests  
- QR code works for a limited time (expiry system)  

### 🧑‍🏫 HOD Features
- View all students’ requests  
- Approve or reject requests  
- On approval:
  - Unique QR token generated  
  - SMS sent to parents  
  - QR stored in system for verification  

### 🛂 Guard / Security Features
- Scan QR  
- Validate:
  - Token authenticity  
  - Expiry  
  - Whether QR already used  
- Provides instant “Approved / Rejected / Expired” message  

---

## 🛠 Tech Stack

| Component | Technology Used |
|----------|-----------------|
| Backend | Python, Flask |
| Database | MySQL |
| OTP & SMS | Twilio API |
| QR Generation | `qrcode` Python library |
| Deployment | Render |
| Frontend | HTML, CSS, Tailwind-inspired UI |

---

## 📁 Project Structure

