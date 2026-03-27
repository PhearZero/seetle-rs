#include "libtropic.h"
#include "libtropic_port_mock.h"
#include <stdlib.h>
#include <string.h>

#include <stdio.h>

lt_handle_t* lt_seelte_create_handle(void) {
    printf("lt_seelte_create_handle start\n");
    lt_handle_t *h = (lt_handle_t*)malloc(sizeof(lt_handle_t));
    if (!h) return NULL;
    memset(h, 0, sizeof(lt_handle_t));
    
    lt_dev_mock_t *mock_dev = (lt_dev_mock_t*)malloc(sizeof(lt_dev_mock_t));
    if (!mock_dev) {
        free(h);
        return NULL;
    }
    memset(mock_dev, 0, sizeof(lt_dev_mock_t));
    h->l2.device = mock_dev;
    printf("lt_seelte_create_handle end, h=%p, dev=%p\n", (void*)h, (void*)mock_dev);
    return h;
}

void lt_seelte_free_handle(lt_handle_t *h) {
    if (h) {
        if (h->l2.device) free(h->l2.device);
        free(h);
    }
}
