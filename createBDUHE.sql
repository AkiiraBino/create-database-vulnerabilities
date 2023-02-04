use vulnerabilities;
create table helmert_encoder_cvss20(id int auto_increment primary key, AV_0 TINYINT, AV_1 TINYINT, AC_0 TINYINT, AC_1 TINYINT, AU_0 TINYINT, AU_1 TINYINT,
 C_0 TINYINT, C_1 TINYINT, I_0 TINYINT, I_1 TINYINT, A_0 TINYINT, A_1 TINYINT);
create table helmert_encoder_cvss30(id int auto_increment primary key, AV_0 TINYINT, AV_1 TINYINT, AV_2 TINYINT, AC_0 TINYINT, PR_0 TINYINT,
 PR_1 TINYINT, UI_0 TINYINT, S_0 TINYINT, C_0 TINYINT, C_1 TINYINT, I_0 TINYINT, I_1 TINYINT, A_0 TINYINT, A_1 TINYINT);
 create table helmert_encoder_cvss31(id int auto_increment primary key, AV_0 TINYINT, AV_1 TINYINT, AV_2 TINYINT, AC_0 TINYINT, PR_0 TINYINT,
 PR_1 TINYINT, UI_0 TINYINT, S_0 TINYINT, C_0 TINYINT, C_1 TINYINT, I_0 TINYINT, I_1 TINYINT, A_0 TINYINT, A_1 TINYINT);