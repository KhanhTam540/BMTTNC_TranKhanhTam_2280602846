from SinhVien import SinhVien
from QuanLySinhVien import QuanLySinhVien

qlsv = QuanLySinhVien()

while True:
    print("\n========== CHUONG TRINH QUAN LY SINH VIEN ==========")
    print("1. Them sinh vien")
    print("2. Cap nhat thong tin sinh vien")
    print("3. Xoa sinh vien")
    print("4. Tim kiem sinh vien theo ten")
    print("5. Sap xep sinh vien theo diem trung binh")
    print("6. Sap xep sinh vien theo ten")
    print("7. Hien thi danh sach sinh vien")
    print("0. Thoat")
    key = int(input("Nhap tuy chon: "))

    if key == 1:
        qlsv.nhapSinhVien()
        print("Them sinh vien thanh cong!")
    elif key == 2:
        if qlsv.soLuongSinhVien() > 0:
            ID = int(input("Nhap ID: "))
            qlsv.updateSinhVien(ID)
        else:
            print("Danh sach sinh vien trong!")
    elif key == 3:
        if qlsv.soLuongSinhVien() > 0:
            ID = int(input("Nhap ID: "))
            if qlsv.deleteById(ID):
                print(f"Sinh vien co id = {ID} da bi xoa.")
            else:
                print(f"Sinh vien co id = {ID} khong ton tai.")
        else:
            print("Danh sach sinh vien trong!")
    elif key == 4:
        if qlsv.soLuongSinhVien() > 0:
            name = input("Nhap ten sinh vien can tim: ")
            result = qlsv.findByName(name)
            qlsv.showSinhVien(result)
        else:
            print("Danh sach sinh vien trong!")
    elif key == 5:
        if qlsv.soLuongSinhVien() > 0:
            qlsv.sortByDiemTB()
            qlsv.showSinhVien(qlsv.listSinhVien)
        else:
            print("Danh sach sinh vien trong!")
    elif key == 6:
        if qlsv.soLuongSinhVien() > 0:
            qlsv.sortByName()
            qlsv.showSinhVien(qlsv.listSinhVien)
        else:
            print("Danh sach sinh vien trong!")
    elif key == 7:
        if qlsv.soLuongSinhVien() > 0:
            qlsv.showSinhVien(qlsv.listSinhVien)
        else:
            print("Danh sach sinh vien trong!")
    elif key == 0:
        break
    else:
        print("Hay chon chuc nang trong menu.")
