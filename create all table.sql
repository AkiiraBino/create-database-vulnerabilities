
use vulnerabilities;
create table original_cvss20 (id int auto_increment primary key, name varchar(30),class varchar(11), score decimal(3, 1),
 AV char(1), AC char(1), AU char(1), C char(1), I char(1), A char(1));
 
create table original_cvss30 (id int auto_increment primary key, name varchar(30), class varchar(11),
 AV char(1), AC char(1), PR char(1), UI char(1), S char(1),
C char(1), I char(1), A char(1));

create table original_cvss31 (id int auto_increment primary key, name varchar(30), class varchar(11), score decimal(3, 1),
 AV char(1), AC char(1), PR char(1), UI char(1), S char(1),
C char(1), I char(1), A char(1));

create table backward_difference_encoder_cvss20 (id int auto_increment primary key, AV_2 decimal(7, 6), AV_0 decimal(7, 6), AV_1 decimal(7, 6), AC_0 decimal(7, 6), Au_2 decimal(7, 6),
 Au_0 decimal(7, 6), Au_1 decimal(7, 6), I_0 decimal(7, 6), I_1 decimal(7, 6), C_2 decimal(7, 6), C_0 decimal(7, 6), C_1 decimal(7, 6), A_0 decimal(7, 6), A_1 decimal(7, 6));

create table backward_difference_encoder_cvss31 (id int auto_increment primary key, AV_0 decimal(7, 6), AV_1 decimal(7, 6), AV_2 decimal(7, 6), AC_1 decimal(7, 6), AC_0 decimal(7, 6),
 PR_0 decimal(7, 6), PR_1 decimal(7, 6), UI_0 decimal(7, 6),  S_0 decimal(7, 6), I_2 decimal(7, 6), I_0 decimal(7, 6), I_1 decimal(7, 6), C_0 decimal(7, 6), C_1 decimal(7, 6),
 A_2 decimal(7, 6), A_0 decimal(7, 6), A_1 decimal(7, 6));

create table backward_difference_encoder_cvss30 (id int auto_increment primary key, AV_0 decimal(7, 6), AV_1 decimal(7, 6), AV_2 decimal(7, 6), AC_1 decimal(7, 6), AC_0 decimal(7, 6),
 PR_0 decimal(7, 6), PR_1 decimal(7, 6),  UI_1 decimal(7, 6), UI_0 decimal(7, 6),  S_0 decimal(7, 6), I_2 decimal(7, 6), I_0 decimal(7, 6), I_1 decimal(7, 6),
 C_0 decimal(7, 6), C_1 decimal(7, 6), A_2 decimal(7, 6), A_0 decimal(7, 6), A_1 decimal(7, 6));
 
 create table binary_encoder_cvss30(id int auto_increment primary key, AV_0 bool, AV_1 bool, AV_2 bool, AC_0 bool, AC_1 bool, PR_0 bool, PR_1 bool, UI_0 bool, UI_1 bool,
S_0 bool, S_1 bool, C_0 bool, C_1 bool, I_0 bool, I_1 bool, A_0 bool, A_1 bool);

create table binary_encoder_cvss31(id int auto_increment primary key, AV_0 bool, AV_1 bool, AV_2 bool, AC_0 bool, AC_1 bool, PR_0 bool, PR_1 bool, UI_0 bool, UI_1 bool,
S_0 bool, S_1 bool, C_0 bool, C_1 bool, I_0 bool, I_1 bool, A_0 bool, A_1 bool);

create table binary_encoder_cvss20(id int auto_increment primary key, AV_0 bool, AV_1 bool, AC_0 bool, AC_1 bool, AU_0 bool, AU_1 bool,
C_0 bool, C_1 bool, I_0 bool, I_1 bool, A_0 bool, A_1 bool);

create table helmert_encoder_cvss20(id int auto_increment primary key, AV_0 TINYINT, AV_1 TINYINT, AC_0 TINYINT, AC_1 TINYINT, AU_0 TINYINT, AU_1 TINYINT,
 C_0 TINYINT, C_1 TINYINT, I_0 TINYINT, I_1 TINYINT, A_0 TINYINT, A_1 TINYINT);

create table helmert_encoder_cvss30(id int auto_increment primary key, AV_0 TINYINT, AV_1 TINYINT, AV_2 TINYINT, AC_0 TINYINT, PR_0 TINYINT,
 PR_1 TINYINT, UI_0 TINYINT, S_0 TINYINT, C_0 TINYINT, C_1 TINYINT, I_0 TINYINT, I_1 TINYINT, A_0 TINYINT, A_1 TINYINT);
 
 create table helmert_encoder_cvss31(id int auto_increment primary key, AV_0 TINYINT, AV_1 TINYINT, AV_2 TINYINT, AC_0 TINYINT, PR_0 TINYINT,
 PR_1 TINYINT, UI_0 TINYINT, S_0 TINYINT, C_0 TINYINT, C_1 TINYINT, I_0 TINYINT, I_1 TINYINT, A_0 TINYINT, A_1 TINYINT);
 
 create table label_encoder_cvss20 (id int auto_increment primary key, AV TINYINT UNSIGNED, AC TINYINT UNSIGNED, AU TINYINT UNSIGNED,
 C TINYINT UNSIGNED, I TINYINT UNSIGNED, A TINYINT UNSIGNED);
 
create table label_encoder_cvss30 (id int auto_increment primary key,
AV TINYINT UNSIGNED, AC TINYINT UNSIGNED, PR TINYINT UNSIGNED, UI TINYINT UNSIGNED, S TINYINT UNSIGNED,
C TINYINT UNSIGNED, I TINYINT UNSIGNED, A TINYINT UNSIGNED);

create table label_encoder_cvss31 (id int auto_increment primary key,
 AV TINYINT UNSIGNED, AC TINYINT UNSIGNED, PR TINYINT UNSIGNED, UI TINYINT UNSIGNED, S TINYINT UNSIGNED,
C TINYINT UNSIGNED, I TINYINT UNSIGNED, A TINYINT UNSIGNED);

create table one_hot_encoder_cvss30 (id int auto_increment primary key, AV_A bool, AV_L bool, AV_N bool, AV_P bool,
 AC_H bool, AC_L bool, PR_H bool, PR_L bool, PR_N bool, UI_N bool, UI_R bool,
 S_C bool, S_U	bool, I_H bool, I_L bool, I_N bool, C_H bool, C_L bool, C_N bool, A_H bool,  A_L bool,  A_N bool);
 
create table one_hot_encoder_cvss31 (id int auto_increment primary key, AV_A bool, AV_L bool, AV_N bool, AV_P bool,
 AC_H bool, AC_L bool, PR_H bool, PR_L bool, PR_N bool, UI_N bool, UI_R bool,
 S_C bool, S_U	bool, I_H bool, I_L bool, I_N bool, C_H bool, C_L bool, C_N bool, A_H bool,  A_L bool,  A_N bool);

create table one_hot_encoder_cvss20 (id int auto_increment primary key, AV_A bool, AV_L bool, AV_N bool,
 AC_H bool, AC_L bool, AC_M bool,  AU_M bool, AU_N bool, AU_S bool, I_C bool, I_N bool, I_P bool, C_C bool, C_N bool, C_P bool, A_C bool,  A_N bool,  A_P bool);
 
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

create table BE20_to_original20(id int auto_increment primary key, BE_id int not null, original_id int not null, foreign key (BE_id) references binary_encoder_cvss20(id),
foreign key (original_id) references original_cvss20(id));

create table BE30_to_original30(id int auto_increment primary key, BE_id int not null, original_id int not null, foreign key (BE_id) references binary_encoder_cvss30(id),
foreign key (original_id) references original_cvss30(id));

create table BE31_to_original31(id int auto_increment primary key, BE_id int not null, original_id int not null, foreign key (BE_id) references binary_encoder_cvss31(id),
foreign key (original_id) references original_cvss31(id));

create table HE20_to_original20(id int auto_increment primary key, HE_id int not null, original_id int not null, foreign key (HE_id) references helmert_encoder_cvss20(id),
foreign key (original_id) references original_cvss20(id));

create table HE30_to_original30(id int auto_increment primary key, HE_id int not null, original_id int not null, foreign key (HE_id) references helmert_encoder_cvss30(id),
foreign key (original_id) references original_cvss30(id));

create table HE31_to_original31(id int auto_increment primary key, HE_id int not null, original_id int not null, foreign key (HE_id) references helmert_encoder_cvss31(id),
foreign key (original_id) references original_cvss31(id));

create table label20_to_original20(id int auto_increment primary key, label_id int not null, original_id int not null, foreign key (label_id) references label_encoder_cvss20(id),
foreign key (original_id) references original_cvss20(id));

create table label30_to_original30(id int auto_increment primary key, label_id int not null, original_id int not null, foreign key (label_id) references label_encoder_cvss30(id),
foreign key (original_id) references original_cvss30(id));
create table label31_to_original31(id int auto_increment primary key, label_id int not null, original_id int not null, foreign key (label_id) references label_encoder_cvss31(id),
foreign key (original_id) references original_cvss31(id));

create table TE20_to_original20(id int auto_increment primary key, target_encoder_id int not null, original_id int not null, foreign key (target_encoder_id) references target_encoder_cvss20(id),
foreign key (original_id) references original_cvss20(id));

create table TE30_to_original30(id int auto_increment primary key, target_encoder_id int not null, original_id int not null, foreign key (target_encoder_id) references target_encoder_cvss30(id),
foreign key (original_id) references original_cvss30(id));

create table TE31_to_original31(id int auto_increment primary key, target_encoder_id int not null, original_id int not null, foreign key (target_encoder_id) references target_encoder_cvss31(id),
foreign key (original_id) references original_cvss31(id));

create table OHE20_to_original20(id int auto_increment primary key, OHE_id int not null, original_id int not null, foreign key (OHE_id) references one_hot_encoder_cvss20(id),
foreign key (original_id) references original_cvss20(id));

create table OHE30_to_original30(id int auto_increment primary key, OHE_id int not null, original_id int not null, foreign key (OHE_id) references one_hot_encoder_cvss30(id),
foreign key (original_id) references original_cvss30(id));

create table OHE31_to_original31(id int auto_increment primary key, OHE_id int not null, original_id int not null, foreign key (OHE_id) references one_hot_encoder_cvss31(id),
foreign key (original_id) references original_cvss31(id));

create table BDE20_to_original20(id int auto_increment primary key, BDE_id int not null, original_id int not null, foreign key (BDE_id) references backward_difference_encoder_cvss20(id),
foreign key (original_id) references original_cvss20(id));

create table BDE30_to_original30(id int auto_increment primary key, BDE_id int not null, original_id int not null, foreign key (BDE_id) references backward_difference_encoder_cvss30(id),
foreign key (original_id) references original_cvss30(id));

create table BDE31_to_original31(id int auto_increment primary key, BDE_id int not null, original_id int not null, foreign key (BDE_id) references backward_difference_encoder_cvss31(id),
foreign key (original_id) references original_cvss31(id));