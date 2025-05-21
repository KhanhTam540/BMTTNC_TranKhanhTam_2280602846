from SinhVien import SinhVien

class QuanLySinhVien:
    listSinhVien = []
    
    def generateID(self):
        maxId = 1
        if self.soLuongSinhVien() > 0:
            maxId = self.listSinhVien[0].id
            for sv in self.listSinhVien:
                if maxId < sv.id:
                    maxId = sv.id
            maxId = maxId + 1
        return maxId

    def soLuongSinhVien(self):
        return len(self.listSinhVien)

    def nhapSinhVien(self):
        svId = self.generateID()
        name = input("Nhap ten sinh vien: ")
        sex = input("Nhap gioi tinh sinh vien: ")
        major = input("Nhap chuyen nganh cua sinh vien: ")
        diemTB = float(input("Nhap diem cua sinh vien: "))
        sv = SinhVien(svId, name, sex, major, diemTB)
        self.xepLoaiHocLuc(sv)
        self.listSinhVien.append(sv)

    def updateSinhVien(self, ID):
        sv = self.findById(ID)
        if sv:
            name = input("Nhap ten cho sinh vien: ")
            sex = input("Nhap gioi tinh cho sinh vien: ")
            major = input("Nhap chuyen nganh cua sinh vien: ")  
            diemTB = float(input("Nhap diem cho sinh vien: "))
            sv.name = name
            sv.sex = sex
            sv.major = major
            sv.diemTB = diemTB
            self.xepLoaiHocLuc(sv)
        else:
            print(f"Sinh Vien co ID = {ID} khong ton tai")
    
    def sortByID(self):
        self.listSinhVien.sort(key=lambda x: x.id, reverse=False)
        
    def sortByName(self):
        self.listSinhVien.sort(key=lambda x: x.name, reverse=False)
        
    def sortByDiemTB(self):
        self.listSinhVien.sort(key=lambda x: x.diemTB, reverse=False)

    def findById(self, ID):
        for sv in self.listSinhVien:
            if sv.id == ID:
                return sv
        return None
    
    def findByName(self, keyword):
        return [sv for sv in self.listSinhVien if keyword.upper() in sv.name.upper()]
    
    def deleteById(self, ID):
        sv = self.findById(ID)
        if sv:
            self.listSinhVien.remove(sv)
            return True
        return False

    def xepLoaiHocLuc(self, sv):
        if sv.diemTB >= 8:
            sv.hocLuc = "Gioi"
        elif sv.diemTB >= 6.5:
            sv.hocLuc = "Kha"
        elif sv.diemTB >= 5:
            sv.hocLuc = "Trung binh"
        else:
            sv.hocLuc = "Yeu"

    def showSinhVien(self, listSV):
        if listSV:
            print("{:<8} {:<20} {:<8} {:<15} {:<6} {:<10}".format("ID", "Ho ten", "Gioi tinh", "Chuyen nganh", "Diem", "Hoc luc"))
            for sv in listSV:
                print("{:<8} {:<20} {:<8} {:<15} {:<6} {:<10}".format(sv.id, sv.name, sv.sex, sv.major, sv.diemTB, sv.hocLuc))
        else:
            print("Danh sach sinh vien trong!")