#!/usr/bin/python
#
# pure Python implementation of optimized simplified SWU map to BLS12-381 G1
# https://github.com/algorand/bls_sigs_ref
#
# This software is (C) 2019 Algorand, Inc.
#
# Licensed under the MIT license (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://opensource.org/licenses/MIT

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from bls12381 import q, h
from hash_to_field import Hp
from fields import Fq, Fq2


def sgn0(x: Fq) -> int:
    # https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-07#section-4.1
    return x.value % 2


def sgn0_Fq2(x: Fq2) -> int:
    # https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-07#section-4.1

    sign_0: int = x[0].value % 2
    zero_0: bool = x[0] == 0
    sign_1: int = x[1].value % 2
    return sign_0 or (zero_0 and sign_1)


# distinguished non-square in Fp for SWU map
xi_1 = Fq(q, 11)
sqrt_mxi_1_cubed = (-(xi_1 ** 3)) ** ((q + 1) // 4)

# 11-isogenous curve parameters
EllP_a = Fq(
    q,
    0x144698A3B8E9433D693A02C96D4982B0EA985383EE66A8D8E8981AEFD881AC98936F8DA0E0F97F5CF428082D584C1D,
)
EllP_b = Fq(
    q,
    0x12E2908D11688030018B12E8753EEE3B2016C1F0F24F4070A0B9C14FCEF35EF55A23215A316CEAA5D1CC48E98E172BE0,
)


#
# Isogeny map evaluation specified by map_coeffs
#
# map_coeffs should be specified as (xnum, xden, ynum, yden)
#
# This function evaluates the isogeny over Jacobian projective coordinates.
# For details, see Section 4.3 of
#    Wahby and Boneh, "Fast and simple constant-time hashing to the BLS12-381 elliptic curve."
#    ePrint # 2019/403, https://ia.cr/2019/403.
def eval_iso(P, map_coeffs):
    (x, y, z) = P
    mapvals = [None] * 4

    # precompute the required powers of Z^2
    maxord = max(len(coeffs) for coeffs in map_coeffs)
    zpows = [None] * maxord
    zpows[0] = pow(z, 0)
    zpows[1] = pow(z, 2)
    for idx in range(2, len(zpows)):
        zpows[idx] = zpows[idx - 1] * zpows[1]

    # compute the numerator and denominator of the X and Y maps via Horner's rule
    for (idx, coeffs) in enumerate(map_coeffs):
        coeffs_z = [
            zpow * c for (zpow, c) in zip(reversed(coeffs), zpows[: len(coeffs)])
        ]
        tmp = coeffs_z[0]
        for coeff in coeffs_z[1:]:
            tmp *= x
            tmp += coeff
        mapvals[idx] = tmp

    # xden is of order 1 less than xnum, so need to multiply it by an extra factor of Z^2
    assert len(map_coeffs[1]) + 1 == len(map_coeffs[0])
    mapvals[1] *= zpows[1]

    # multiply result of Y map by the y-coordinate y / z^3
    mapvals[2] *= y
    mapvals[3] *= pow(z, 3)

    Z = mapvals[1] * mapvals[3]
    X = mapvals[0] * mapvals[3] * Z
    Y = mapvals[2] * mapvals[1] * Z * Z
    return (X, Y, Z)


#
# Simplified SWU map for Ell1'
#
# map an element of Fp to the curve Ell1', 11-isogenous to Ell1
def osswu_help(t):
    assert isinstance(t, Fq)

    # first, compute X0(t), detecting and handling exceptional case
    num_den_common = xi_1 ** 2 * t ** 4 + xi_1 * t ** 2
    x0_num = EllP_b * (num_den_common + 1)
    x0_den = -EllP_a * num_den_common
    x0_den = EllP_a * xi_1 if x0_den == 0 else x0_den

    # g(X0(t))
    gx0_den = pow(x0_den, 3)
    gx0_num = EllP_b * gx0_den
    gx0_num += EllP_a * x0_num * pow(x0_den, 2)
    gx0_num += pow(x0_num, 3)

    # try taking sqrt of g(X0(t))
    # this uses the trick for combining division and sqrt from Section 5 of
    # Bernstein, Duif, Lange, Schwabe, and Yang, "High-speed high-security signatures."
    # J Crypt Eng 2(2):77--89, Sept. 2012. http://ed25519.cr.yp.to/ed25519-20110926.pdf
    tmp1 = gx0_num * gx0_den  # u v
    tmp2 = tmp1 * pow(gx0_den, 2)  # u v^3
    sqrt_candidate = tmp1 * pow(tmp2, (q - 3) // 4)

    # did we find it?
    if sqrt_candidate ** 2 * gx0_den == gx0_num:
        # found sqrt(g(X0(t))). Force sign of y to equal sign of t
        (x_num, y) = (x0_num, sqrt_candidate)

    else:
        x1_num = xi_1 * t ** 2 * x0_num
        y1 = sqrt_candidate * t ** 3 * sqrt_mxi_1_cubed
        (x_num, y) = (x1_num, y1)

    # set sign of y equal to sign of t
    y = sgn0(y) * sgn0(t) * y
    assert sgn0(y) == sgn0(t)
    return (x_num * x0_den, y * pow(x0_den, 3), x0_den)


#
# 11-isogeny from Ell1' to Ell1
#
# map coefficients
xnum = (
    Fq(
        q,
        0x11A05F2B1E833340B809101DD99815856B303E88A2D7005FF2627B56CDB4E2C85610C2D5F2E62D6EAEAC1662734649B7,
    ),
    Fq(
        q,
        0x17294ED3E943AB2F0588BAB22147A81C7C17E75B2F6A8417F565E33C70D1E86B4838F2A6F318C356E834EEF1B3CB83BB,
    ),
    Fq(
        q,
        0xD54005DB97678EC1D1048C5D10A9A1BCE032473295983E56878E501EC68E25C958C3E3D2A09729FE0179F9DAC9EDCB0,
    ),
    Fq(
        q,
        0x1778E7166FCC6DB74E0609D307E55412D7F5E4656A8DBF25F1B33289F1B330835336E25CE3107193C5B388641D9B6861,
    ),
    Fq(
        q,
        0xE99726A3199F4436642B4B3E4118E5499DB995A1257FB3F086EEB65982FAC18985A286F301E77C451154CE9AC8895D9,
    ),
    Fq(
        q,
        0x1630C3250D7313FF01D1201BF7A74AB5DB3CB17DD952799B9ED3AB9097E68F90A0870D2DCAE73D19CD13C1C66F652983,
    ),
    Fq(
        q,
        0xD6ED6553FE44D296A3726C38AE652BFB11586264F0F8CE19008E218F9C86B2A8DA25128C1052ECADDD7F225A139ED84,
    ),
    Fq(
        q,
        0x17B81E7701ABDBE2E8743884D1117E53356DE5AB275B4DB1A682C62EF0F2753339B7C8F8C8F475AF9CCB5618E3F0C88E,
    ),
    Fq(
        q,
        0x80D3CF1F9A78FC47B90B33563BE990DC43B756CE79F5574A2C596C928C5D1DE4FA295F296B74E956D71986A8497E317,
    ),
    Fq(
        q,
        0x169B1F8E1BCFA7C42E0C37515D138F22DD2ECB803A0C5C99676314BAF4BB1B7FA3190B2EDC0327797F241067BE390C9E,
    ),
    Fq(
        q,
        0x10321DA079CE07E272D8EC09D2565B0DFA7DCCDDE6787F96D50AF36003B14866F69B771F8C285DECCA67DF3F1605FB7B,
    ),
    Fq(
        q,
        0x6E08C248E260E70BD1E962381EDEE3D31D79D7E22C837BC23C0BF1BC24C6B68C24B1B80B64D391FA9C8BA2E8BA2D229,
    ),
)
xden = (
    Fq(
        q,
        0x8CA8D548CFF19AE18B2E62F4BD3FA6F01D5EF4BA35B48BA9C9588617FC8AC62B558D681BE343DF8993CF9FA40D21B1C,
    ),
    Fq(
        q,
        0x12561A5DEB559C4348B4711298E536367041E8CA0CF0800C0126C2588C48BF5713DAA8846CB026E9E5C8276EC82B3BFF,
    ),
    Fq(
        q,
        0xB2962FE57A3225E8137E629BFF2991F6F89416F5A718CD1FCA64E00B11ACEACD6A3D0967C94FEDCFCC239BA5CB83E19,
    ),
    Fq(
        q,
        0x3425581A58AE2FEC83AAFEF7C40EB545B08243F16B1655154CCA8ABC28D6FD04976D5243EECF5C4130DE8938DC62CD8,
    ),
    Fq(
        q,
        0x13A8E162022914A80A6F1D5F43E7A07DFFDFC759A12062BB8D6B44E833B306DA9BD29BA81F35781D539D395B3532A21E,
    ),
    Fq(
        q,
        0xE7355F8E4E667B955390F7F0506C6E9395735E9CE9CAD4D0A43BCEF24B8982F7400D24BC4228F11C02DF9A29F6304A5,
    ),
    Fq(
        q,
        0x772CAACF16936190F3E0C63E0596721570F5799AF53A1894E2E073062AEDE9CEA73B3538F0DE06CEC2574496EE84A3A,
    ),
    Fq(
        q,
        0x14A7AC2A9D64A8B230B3F5B074CF01996E7F63C21BCA68A81996E1CDF9822C580FA5B9489D11E2D311F7D99BBDCC5A5E,
    ),
    Fq(
        q,
        0xA10ECF6ADA54F825E920B3DAFC7A3CCE07F8D1D7161366B74100DA67F39883503826692ABBA43704776EC3A79A1D641,
    ),
    Fq(
        q,
        0x95FC13AB9E92AD4476D6E3EB3A56680F682B4EE96F7D03776DF533978F31C1593174E4B4B7865002D6384D168ECDD0A,
    ),
    Fq(q, 0x1),
)
ynum = (
    Fq(
        q,
        0x90D97C81BA24EE0259D1F094980DCFA11AD138E48A869522B52AF6C956543D3CD0C7AEE9B3BA3C2BE9845719707BB33,
    ),
    Fq(
        q,
        0x134996A104EE5811D51036D776FB46831223E96C254F383D0F906343EB67AD34D6C56711962FA8BFE097E75A2E41C696,
    ),
    Fq(
        q,
        0xCC786BAA966E66F4A384C86A3B49942552E2D658A31CE2C344BE4B91400DA7D26D521628B00523B8DFE240C72DE1F6,
    ),
    Fq(
        q,
        0x1F86376E8981C217898751AD8746757D42AA7B90EEB791C09E4A3EC03251CF9DE405ABA9EC61DECA6355C77B0E5F4CB,
    ),
    Fq(
        q,
        0x8CC03FDEFE0FF135CAF4FE2A21529C4195536FBE3CE50B879833FD221351ADC2EE7F8DC099040A841B6DAECF2E8FEDB,
    ),
    Fq(
        q,
        0x16603FCA40634B6A2211E11DB8F0A6A074A7D0D4AFADB7BD76505C3D3AD5544E203F6326C95A807299B23AB13633A5F0,
    ),
    Fq(
        q,
        0x4AB0B9BCFAC1BBCB2C977D027796B3CE75BB8CA2BE184CB5231413C4D634F3747A87AC2460F415EC961F8855FE9D6F2,
    ),
    Fq(
        q,
        0x987C8D5333AB86FDE9926BD2CA6C674170A05BFE3BDD81FFD038DA6C26C842642F64550FEDFE935A15E4CA31870FB29,
    ),
    Fq(
        q,
        0x9FC4018BD96684BE88C9E221E4DA1BB8F3ABD16679DC26C1E8B6E6A1F20CABE69D65201C78607A360370E577BDBA587,
    ),
    Fq(
        q,
        0xE1BBA7A1186BDB5223ABDE7ADA14A23C42A0CA7915AF6FE06985E7ED1E4D43B9B3F7055DD4EBA6F2BAFAAEBCA731C30,
    ),
    Fq(
        q,
        0x19713E47937CD1BE0DFD0B8F1D43FB93CD2FCBCB6CAF493FD1183E416389E61031BF3A5CCE3FBAFCE813711AD011C132,
    ),
    Fq(
        q,
        0x18B46A908F36F6DEB918C143FED2EDCC523559B8AAF0C2462E6BFE7F911F643249D9CDF41B44D606CE07C8A4D0074D8E,
    ),
    Fq(
        q,
        0xB182CAC101B9399D155096004F53F447AA7B12A3426B08EC02710E807B4633F06C851C1919211F20D4C04F00B971EF8,
    ),
    Fq(
        q,
        0x245A394AD1ECA9B72FC00AE7BE315DC757B3B080D4C158013E6632D3C40659CC6CF90AD1C232A6442D9D3F5DB980133,
    ),
    Fq(
        q,
        0x5C129645E44CF1102A159F748C4A3FC5E673D81D7E86568D9AB0F5D396A7CE46BA1049B6579AFB7866B1E715475224B,
    ),
    Fq(
        q,
        0x15E6BE4E990F03CE4EA50B3B42DF2EB5CB181D8F84965A3957ADD4FA95AF01B2B665027EFEC01C7704B456BE69C8B604,
    ),
)
yden = (
    Fq(
        q,
        0x16112C4C3A9C98B252181140FAD0EAE9601A6DE578980BE6EEC3232B5BE72E7A07F3688EF60C206D01479253B03663C1,
    ),
    Fq(
        q,
        0x1962D75C2381201E1A0CBD6C43C348B885C84FF731C4D59CA4A10356F453E01F78A4260763529E3532F6102C2E49A03D,
    ),
    Fq(
        q,
        0x58DF3306640DA276FAAAE7D6E8EB15778C4855551AE7F310C35A5DD279CD2ECA6757CD636F96F891E2538B53DBF67F2,
    ),
    Fq(
        q,
        0x16B7D288798E5395F20D23BF89EDB4D1D115C5DBDDBCD30E123DA489E726AF41727364F2C28297ADA8D26D98445F5416,
    ),
    Fq(
        q,
        0xBE0E079545F43E4B00CC912F8228DDCC6D19C9F0F69BBB0542EDA0FC9DEC916A20B15DC0FD2EDEDDA39142311A5001D,
    ),
    Fq(
        q,
        0x8D9E5297186DB2D9FB266EAAC783182B70152C65550D881C5ECD87B6F0F5A6449F38DB9DFA9CCE202C6477FAAF9B7AC,
    ),
    Fq(
        q,
        0x166007C08A99DB2FC3BA8734ACE9824B5EECFDFA8D0CF8EF5DD365BC400A0051D5FA9C01A58B1FB93D1A1399126A775C,
    ),
    Fq(
        q,
        0x16A3EF08BE3EA7EA03BCDDFABBA6FF6EE5A4375EFA1F4FD7FEB34FD206357132B920F5B00801DEE460EE415A15812ED9,
    ),
    Fq(
        q,
        0x1866C8ED336C61231A1BE54FD1D74CC4F9FB0CE4C6AF5920ABC5750C4BF39B4852CFE2F7BB9248836B233D9D55535D4A,
    ),
    Fq(
        q,
        0x167A55CDA70A6E1CEA820597D94A84903216F763E13D87BB5308592E7EA7D4FBC7385EA3D529B35E346EF48BB8913F55,
    ),
    Fq(
        q,
        0x4D2F259EEA405BD48F010A01AD2911D9C6DD039BB61A6290E591B36E636A5C871A5C29F4F83060400F8B49CBA8F6AA8,
    ),
    Fq(
        q,
        0xACCBB67481D033FF5852C1E48C50C477F94FF8AEFCE42D28C0F9A88CEA7913516F968986F7EBBEA9684B529E2561092,
    ),
    Fq(
        q,
        0xAD6B9514C767FE3C3613144B45F1496543346D98ADF02267D5CEEF9A00D9B8693000763E3B90AC11E99B138573345CC,
    ),
    Fq(
        q,
        0x2660400EB2E4F3B628BDD0D53CD76F2BF565B94E72927C1CB748DF27942480E420517BD8714CC80D1FADC1326ED06F7,
    ),
    Fq(
        q,
        0xE0FA1D816DDC03E6B24255E0D7819C171C40F65E273B853324EFCD6356CAA205CA2F570F13497804415473A1D634B8F,
    ),
    Fq(q, 0x1),
)


# compute 11-isogeny map from Ell1' to Ell1
def iso11(P):
    return eval_iso(P, (xnum, xden, ynum, yden))


def opt_swu_map(t: Fq, t2: Fq = None):
    Pp = osswu_help(t)
    if t2 is not None:
        Pp2 = osswu_help(t2)
        Pp = Pp + Pp2
    P = iso11(Pp)
    return P * h


def map2curve_osswu(alpha, dst=None):
    return opt_swu_map(*(Fq(q, *hh) for hh in Hp(alpha, 2, dst)))
