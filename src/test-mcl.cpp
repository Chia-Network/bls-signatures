#define CATCH_CONFIG_RUNNER
#include "catch.hpp"
#include "bls.hpp"
#include "test-utils.hpp"
#include "relic.h"
#include "relic_test.h"

using namespace bls;

void dump(const bn_t *v)
{
    const int n = v[0]->used;
    printf("sizeof(dp)=%zd BN_SIZE=%d\n", sizeof(v[0]->dp), BN_SIZE);
    printf("sign=%d, used=%d\n", v[0]->sign, n);
    for (int i = 0; i < n; i++) {
        printf("%016lx ", v[0]->dp[i]);
    }
    printf("\n");
}

void dump(const fp_st *v)
{
    printf("sizeof=%zd\n", sizeof(fp_st));
    for (size_t i = 0; i < sizeof(fp_st) / 8; i++) {
        printf("%016lx ", v[0][i]);
    }
    printf("\n");
    mclBnFp x = *(const mclBnFp*)v[0];
    char buf[128];
    mclBnFp_getStr(buf, sizeof(buf), &x, 16);
    printf("fp=%s\n", buf);
}
void dump(const g1_t *v)
{
    char buf[128];
    fp_write_str(buf, sizeof(buf), v[0]->x, 16);
    printf("%s ", buf);
    printf("\n");dump(&v[0]->x);
    fp_write_str(buf, sizeof(buf), v[0]->y, 16);
    printf("%s ", buf);
    fp_write_str(buf, sizeof(buf), v[0]->z, 16);
    printf("%s ", buf);
    printf("(%d)\n", v[0]->norm);
}

void dump(const mclBnG1 *v)
{
    const int IoEcProj = 1024;
    char buf[256];
    mclBnG1_getStr(buf, sizeof(buf), v, IoEcProj | 16);
    printf("%s\n", buf);
}

TEST_CASE("conv") {
    SECTION("Fr") {
        char buf[128];
        bn_t x, y;
        bn_new(x);
        bn_new(y);
        bn_set_dig(x, 123);
        mclBnFr xx, yy;
        mcl::conv(&xx, &x);
        mclBnFr_getStr(buf, sizeof(buf), &xx, 10);
        REQUIRE(strcmp(buf, "123") == 0);

        const char *s = "1234abcdef1234abcef";
        bn_read_str(x, s, strlen(s), 16);
        mclBnFr_setStr(&xx, s, strlen(s), 16);
        mcl::conv(&yy, &x);
        REQUIRE(mclBnFr_isEqual(&xx, &yy));

        mcl::conv(&y, &xx);
        REQUIRE(bn_cmp(x, y) == CMP_EQ);
    }
    SECTION("G1") {
        char buf[256];
        g1_t x, y, z;
        g1_new(x);
        g1_new(y);
        g1_get_gen(x);
        mclBnG1 xx, yy, zz;
        mcl::conv(&xx, &x);
        g1_dbl(y, x);
        mclBnG1_dbl(&yy, &xx);
        mcl::conv(&z, &yy);
        mcl::conv(&zz, &y);
        REQUIRE(mclBnG1_isEqual(&yy, &zz));
        REQUIRE(g1_cmp(y, z) == CMP_EQ);

        g1_add(x, x, y);
        mclBnG1_add(&xx, &xx, &yy);
        mcl::conv(&zz, &x);
        mcl::conv(&z, &xx);
        REQUIRE(mclBnG1_isEqual(&zz, &xx));
        REQUIRE(g1_cmp(z, x) == CMP_EQ);
    }
    SECTION("G2") {
        char buf[256];
        g2_t x, y, z;
        g2_new(x);
        g2_new(y);
        g2_get_gen(x);
        mclBnG2 xx, yy, zz;
        mcl::conv(&xx, &x);
        g2_dbl(y, x);
        mclBnG2_dbl(&yy, &xx);
        mcl::conv(&z, &yy);
        mcl::conv(&zz, &y);
        REQUIRE(mclBnG2_isEqual(&yy, &zz));
        REQUIRE(g2_cmp(y, z) == CMP_EQ);

        g2_add(x, x, y);
        mclBnG2_add(&xx, &xx, &yy);
        mcl::conv(&zz, &x);
        mcl::conv(&z, &xx);
        REQUIRE(mclBnG2_isEqual(&zz, &xx));
        REQUIRE(g2_cmp(z, x) == CMP_EQ);
    }
    SECTION("bench") {
        const char *rStr = "72EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001";
        const double numIters = 1000;
        g1_t x;
        g2_t y;
        bn_t s;
        mclBnG1 xx, t1;
        mclBnG2 yy, t2;
        mclBnFr ss;
        g1_new(x);
        g2_new(y);
        bn_new(s);
        g1_get_gen(x);
        g2_get_gen(y);
        bn_read_str(s, rStr, strlen(rStr), 16);
        mcl::conv(&xx, &x);
        mcl::conv(&yy, &y);
        mcl::conv(&ss, &s);

        auto start = startStopwatch();
        for (size_t i = 0; i < numIters; i++) {
            g1_mul(x, x, s);
        }
        endStopwatch("g1_mul", start, numIters);

        start = startStopwatch();
        for (size_t i = 0; i < numIters; i++) {
            mclBnG1_mul(&xx, &xx, &ss);
        }
        endStopwatch("mclBnG1_mul", start, numIters);

        mcl::conv(&t1, &x);
        REQUIRE(mclBnG1_isEqual(&t1, &xx));

        start = startStopwatch();
        for (size_t i = 0; i < numIters; i++) {
            g2_mul(y, y, s);
        }
        endStopwatch("g2_mul", start, numIters);
        start = startStopwatch();
        for (size_t i = 0; i < numIters; i++) {
            mclBnG2_mul(&yy, &yy, &ss);
        }
        endStopwatch("mclBnG2_mul", start, numIters);

        mcl::conv(&t2, &y);
        REQUIRE(mclBnG2_isEqual(&t2, &yy));

        gt_t e;
        gt_new(e);
        mclBnGT ee;
        start = startStopwatch();
        for (size_t i = 0; i < numIters; i++) {
            pc_map_sim(e, &x, &y, 1);
        }
        endStopwatch("pc_map_sim(len=1)", start, numIters);
        start = startStopwatch();
        for (size_t i = 0; i < numIters; i++) {
            mclBn_pairing(&ee, &xx, &yy);
        }
        endStopwatch("mclBn_pairing", start, numIters);
    }
}

int main(int argc, char* argv[]) {
    core_init();
    ep_param_set_any_pairf();
    mclBn_init(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
    int result = Catch::Session().run(argc, argv);
    return result;
}
