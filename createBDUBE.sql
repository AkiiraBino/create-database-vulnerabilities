use vulnerabilities;
create table binary_encoder_cvss30(id int auto_increment primary key, AV_0 bool, AV_1 bool, AV_2 bool, AC_0 bool, AC_1 bool, PR_0 bool, PR_1 bool, UI_0 bool, UI_1 bool,
S_0 bool, S_1 bool, C_0 bool, C_1 bool, I_0 bool, I_1 bool, A_0 bool, A_1 bool);
create table binary_encoder_cvss31(id int auto_increment primary key, AV_0 bool, AV_1 bool, AV_2 bool, AC_0 bool, AC_1 bool, PR_0 bool, PR_1 bool, UI_0 bool, UI_1 bool,
S_0 bool, S_1 bool, C_0 bool, C_1 bool, I_0 bool, I_1 bool, A_0 bool, A_1 bool);
create table binary_encoder_cvss20(id int auto_increment primary key, AV_0 bool, AV_1 bool, AC_0 bool, AC_1 bool, AU_0 bool, AU_1 bool,
C_0 bool, C_1 bool, I_0 bool, I_1 bool, A_0 bool, A_1 bool);