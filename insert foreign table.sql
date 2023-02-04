use vulnerabilities;

insert into bde20_to_original20(BDE_id, original_id) select bde.id, original.id from backward_difference_encoder_cvss20 as bde
join original_cvss20 as original on original.id = bde.id;

insert into bde30_to_original30(BDE_id, original_id) select bde.id, original.id from backward_difference_encoder_cvss30 as bde
join original_cvss30 as original on original.id = bde.id;

insert into bde31_to_original31(BDE_id, original_id) select bde.id, original.id from backward_difference_encoder_cvss31 as bde
join original_cvss31 as original on original.id = bde.id;

insert into be20_to_original20(BE_id, original_id) select be.id, original.id from binary_encoder_cvss20 as be
join original_cvss20 as original on original.id = be.id;

insert into be30_to_original30(BE_id, original_id) select be.id, original.id from binary_encoder_cvss30 as be
join original_cvss30 as original on original.id = be.id;

insert into be31_to_original31(BE_id, original_id) select be.id, original.id from binary_encoder_cvss31 as be
join original_cvss31 as original on original.id = be.id;

insert into he20_to_original20(HE_id, original_id) select he.id, original.id from helmert_encoder_cvss20 as he
join original_cvss20 as original on original.id = he.id;

insert into he30_to_original30(HE_id, original_id) select he.id, original.id from helmert_encoder_cvss30 as he
join original_cvss30 as original on original.id = he.id;

insert into he31_to_original31(HE_id, original_id) select he.id, original.id from helmert_encoder_cvss31 as he
join original_cvss31 as original on original.id = he.id;

insert into label20_to_original20(label_id, original_id) select label.id, original.id from label_encoder_cvss20 as label
join original_cvss20 as original on original.id = label.id;

insert into label30_to_original30(label_id, original_id) select label.id, original.id from label_encoder_cvss30 as label
join original_cvss30 as original on original.id = label.id;

insert into label31_to_original31(label_id, original_id) select label.id, original.id from label_encoder_cvss31 as label
join original_cvss31 as original on original.id = label.id;

insert into ohe20_to_original20(OHE_id, original_id) select ohe.id, original.id from one_hot_encoder_cvss20 as ohe
join original_cvss20 as original on original.id = ohe.id;

insert into ohe30_to_original30(OHE_id, original_id) select ohe.id, original.id from one_hot_encoder_cvss30 as ohe
join original_cvss30 as original on original.id = ohe.id;

insert into ohe31_to_original31(OHE_id, original_id) select ohe.id, original.id from one_hot_encoder_cvss31 as ohe
join original_cvss31 as original on original.id = ohe.id;

insert into te20_to_original20(target_encoder_id, original_id) select te.id, original.id from target_encoder_cvss20 as te
join original_cvss20 as original on original.id = te.id;

insert into te30_to_original30(target_encoder_id, original_id) select te.id, original.id from target_encoder_cvss30 as te
join original_cvss30 as original on original.id = te.id;

insert into te31_to_original31(target_encoder_id, original_id) select te.id, original.id from target_encoder_cvss31 as te
join original_cvss31 as original on original.id = te.id;