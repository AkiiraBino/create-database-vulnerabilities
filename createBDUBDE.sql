use vulnerabilities;
create table backward_difference_encoder_cvss20 (id int auto_increment primary key, AV_2 decimal(4, 3), AV_0 decimal(4, 3), AV_1 decimal(4, 3), AC_0 decimal(4, 3), Au_2 decimal(4, 3),
 Au_0 decimal(4, 3), Au_1 decimal(4, 3), I_0 decimal(4, 3), I_1 decimal(4, 3), C_2 decimal(4, 3), C_0 decimal(4, 3), C_1 decimal(4, 3), A_0 decimal(4, 3), A_1 decimal(4, 3));
create table backward_difference_encoder_cvss31 (id int auto_increment primary key, AV_0 decimal(4, 3), AV_1 decimal(4, 3), AV_2 decimal(4, 3), AC_1 decimal(4, 3), AC_0 decimal(4, 3),
 PR_0 decimal(4, 3), PR_1 decimal(4, 3), UI_0 decimal(4, 3),  S_0 decimal(4, 3), I_2 decimal(4, 3), I_0 decimal(4, 3), I_1 decimal(4, 3), C_0 decimal(4, 3), C_1 decimal(4, 3),
 A_2 decimal(4, 3), A_0 decimal(4, 3), A_1 decimal(4, 3));
create table backward_difference_encoder_cvss30 (id int auto_increment primary key, AV_0 decimal(4, 3), AV_1 decimal(4, 3), AV_2 decimal(4, 3), AC_1 decimal(4, 3), AC_0 decimal(4, 3),
 PR_0 decimal(4, 3), PR_1 decimal(4, 3),  UI_1 decimal(4, 3), UI_0 decimal(4, 3),  S_0 decimal(4, 3), I_2 decimal(4, 3), I_0 decimal(4, 3), I_1 decimal(4, 3),
 C_0 decimal(4, 3), C_1 decimal(4, 3), A_2 decimal(4, 3), A_0 decimal(4, 3), A_1 decimal(4, 3));
 