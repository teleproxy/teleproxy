/* Standalone test for direct_dc_lookup() — exercises DC ID mapping.
   Build: make -C fuzz test
   Covers: production, media, test, CDN, and invalid DC IDs. */

#include <assert.h>
#include <stdio.h>
#include "mtproto/mtproto-dc-table.h"

static void test_production_dcs (void) {
  for (int i = 1; i <= 5; i++) {
    const struct dc_entry *e = direct_dc_lookup (i);
    assert (e && "production DC not found");
    assert (e->dc_id == i);
    assert (e->addr_count > 0);
    assert (e->addrs[0].port == 443);
  }
  printf ("  production DCs 1-5: OK\n");
}

static void test_media_dcs (void) {
  for (int i = 1; i <= 5; i++) {
    const struct dc_entry *e = direct_dc_lookup (-i);
    assert (e && "media DC not found");
    assert (e->dc_id == i);
  }
  printf ("  media DCs -1..-5: OK\n");
}

static void test_test_dcs (void) {
  for (int i = 1; i <= 3; i++) {
    const struct dc_entry *e = direct_dc_lookup (10000 + i);
    assert (e && "test DC not found");
    assert (e->dc_id == i);
  }
  /* Test DC 4 and 5 don't exist in the test table */
  assert (direct_dc_lookup (10004) == NULL);
  assert (direct_dc_lookup (10005) == NULL);
  printf ("  test DCs 10001-10003: OK\n");
}

static void test_cdn_dcs (void) {
  /* CDN DCs (200 + base) should map to the base production DC */
  for (int i = 1; i <= 5; i++) {
    const struct dc_entry *e = direct_dc_lookup (200 + i);
    assert (e && "CDN DC not found");
    assert (e->dc_id == i);
  }
  printf ("  CDN DCs 201-205: OK\n");
}

static void test_negative_cdn_dcs (void) {
  /* Media CDN: -203 -> abs -> 203 -> CDN strip -> 3 */
  for (int i = 1; i <= 5; i++) {
    const struct dc_entry *e = direct_dc_lookup (-(200 + i));
    assert (e && "media CDN DC not found");
    assert (e->dc_id == i);
  }
  printf ("  media CDN DCs -201..-205: OK\n");
}

static void test_test_cdn_dcs (void) {
  /* Test CDN: 10203 -> test strip -> 203 -> CDN strip -> 3 */
  for (int i = 1; i <= 3; i++) {
    const struct dc_entry *e = direct_dc_lookup (10000 + 200 + i);
    assert (e && "test CDN DC not found");
    assert (e->dc_id == i);
  }
  printf ("  test CDN DCs 10201-10203: OK\n");
}

static void test_invalid_dcs (void) {
  assert (direct_dc_lookup (0) == NULL);
  assert (direct_dc_lookup (6) == NULL);
  assert (direct_dc_lookup (100) == NULL);
  assert (direct_dc_lookup (200) == NULL);  /* 200 itself, not 201+ */
  assert (direct_dc_lookup (300) == NULL);
  assert (direct_dc_lookup (999) == NULL);
  assert (direct_dc_lookup (-6) == NULL);
  printf ("  invalid DCs (0, 6, 100, 200, 300, 999, -6): OK\n");
}

static void test_dc_override (void) {
  /* Override takes priority over built-in table */
  assert (direct_dc_override (42, "10.0.0.1", 443) == 0);
  const struct dc_entry *e = direct_dc_lookup (42);
  assert (e && "overridden DC not found");
  assert (e->dc_id == 42);

  /* CDN DC with override: override table is checked before CDN stripping */
  assert (direct_dc_override (203, "10.0.0.2", 443) == 0);
  e = direct_dc_lookup (203);
  assert (e && "overridden CDN DC not found");
  assert (e->dc_id == 203);  /* override entry, not stripped to 3 */

  printf ("  dc-override: OK\n");
}

int main (void) {
  printf ("dc_lookup tests:\n");
  test_production_dcs ();
  test_media_dcs ();
  test_test_dcs ();
  test_cdn_dcs ();
  test_negative_cdn_dcs ();
  test_test_cdn_dcs ();
  test_invalid_dcs ();
  test_dc_override ();
  printf ("all dc_lookup tests passed\n");
  return 0;
}
