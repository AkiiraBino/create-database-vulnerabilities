use vulnerabilities;
create table target_encoder_cvss31(id int auto_increment primary key, AV_Class_1 decimal(7, 6), AV_Class_2 decimal(7, 6), AV_Class_3 decimal(7, 6), AV_Class_4 decimal(7, 6),
 AC_Class_1 decimal(7, 6), AC_Class_2 decimal(7, 6), AC_Class_3 decimal(7, 6), AC_Class_4 decimal(7, 6), PR_Class_1 decimal(7, 6), PR_Class_2 decimal(7, 6),
PR_Class_3 decimal(7, 6), PR_Class_4 decimal(7, 6), UI_Class_1 decimal(7, 6), UI_Class_2 decimal(7, 6), UI_Class_3 decimal(7, 6),
UI_Class_4 decimal(7, 6), S_Class_1 decimal(7, 6), S_Class_2 decimal(7, 6), S_Class_3 decimal(7, 6), S_Class_4 decimal(7, 6),
C_Class_1 decimal(7, 6), C_Class_2 decimal(7, 6), C_Class_3 decimal(7, 6), C_Class_4 decimal(7, 6), I_Class_1 decimal(7, 6),
I_Class_2 decimal(7, 6), I_Class_3 decimal(7, 6), I_Class_4 decimal(7, 6), A_Class_1 decimal(7, 6), A_Class_2 decimal(7, 6),
A_Class_3 decimal(7, 6), A_Class_4 decimal(7, 6));
create table target_encoder_cvss30(id int auto_increment primary key, AV_Class_1 decimal(7, 6), AV_Class_2 decimal(7, 6), AV_Class_3 decimal(7, 6), AV_Class_4 decimal(7, 6),
 AC_Class_1 decimal(7, 6), AC_Class_2 decimal(7, 6), AC_Class_3 decimal(7, 6), AC_Class_4 decimal(7, 6), PR_Class_1 decimal(7, 6), PR_Class_2 decimal(7, 6),
PR_Class_3 decimal(7, 6), PR_Class_4 decimal(7, 6), UI_Class_1 decimal(7, 6), UI_Class_2 decimal(7, 6), UI_Class_3 decimal(7, 6),
UI_Class_4 decimal(7, 6), S_Class_1 decimal(7, 6), S_Class_2 decimal(7, 6), S_Class_3 decimal(7, 6), S_Class_4 decimal(7, 6),
C_Class_1 decimal(7, 6), C_Class_2 decimal(7, 6), C_Class_3 decimal(7, 6), C_Class_4 decimal(7, 6), I_Class_1 decimal(7, 6),
I_Class_2 decimal(7, 6), I_Class_3 decimal(7, 6), I_Class_4 decimal(7, 6), A_Class_1 decimal(7, 6), A_Class_2 decimal(7, 6),
A_Class_3 decimal(7, 6), A_Class_4 decimal(7, 6));
create table target_encoder_cvss20(id int auto_increment primary key, AV_Class_1 decimal(7, 6), AV_Class_2 decimal(7, 6), AV_Class_3 decimal(7, 6), AV_Class_4 decimal(7, 6),
 AC_Class_1 decimal(7, 6), AC_Class_2 decimal(7, 6), AC_Class_3 decimal(7, 6), AC_Class_4 decimal(7, 6), AU_Class_1 decimal(7, 6), AU_Class_2 decimal(7, 6),
AU_Class_3 decimal(7, 6), AU_Class_4 decimal(7, 6), C_Class_1 decimal(7, 6), C_Class_2 decimal(7, 6), C_Class_3 decimal(7, 6), C_Class_4 decimal(7, 6),
I_Class_1 decimal(7, 6), I_Class_2 decimal(7, 6), I_Class_3 decimal(7, 6), I_Class_4 decimal(7, 6), A_Class_1 decimal(7, 6), A_Class_2 decimal(7, 6),
A_Class_3 decimal(7, 6), A_Class_4 decimal(7, 6));
