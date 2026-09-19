package com.yqsh.protector.packer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class Pvm2AdmissionTest {

    @Test
    void classifyMapsKnownFailReasons() {
        assertEquals(Pvm2Admission.SkipReason.unsupported_opcode,
                Pvm2Admission.classify("unsupported opcode 0x26"));
        assertEquals(Pvm2Admission.SkipReason.too_many_regs,
                Pvm2Admission.classify("too many regs (+scratch)"));
        assertEquals(Pvm2Admission.SkipReason.try_catch,
                Pvm2Admission.classify("try start not mapped 12"));
        assertEquals(Pvm2Admission.SkipReason.try_catch,
                Pvm2Admission.classify("tries without handlers"));
        assertEquals(Pvm2Admission.SkipReason.branch,
                Pvm2Admission.classify("bad branch target 40"));
        assertEquals(Pvm2Admission.SkipReason.branch,
                Pvm2Admission.classify("branch too far"));
        assertEquals(Pvm2Admission.SkipReason.type,
                Pvm2Admission.classify("unsupported return [F"));
        assertEquals(Pvm2Admission.SkipReason.other,
                Pvm2Admission.classify("empty"));
        assertEquals(Pvm2Admission.SkipReason.other,
                Pvm2Admission.classify(null));
    }

    @Test
    void parseUnsupportedOpcodeHex() {
        assertEquals(0x26, Pvm2Admission.parseUnsupportedOpcode("unsupported opcode 0x26"));
        assertEquals(0x2b, Pvm2Admission.parseUnsupportedOpcode("unsupported opcode 0x2b at pc"));
        assertNull(Pvm2Admission.parseUnsupportedOpcode("too many regs"));
    }

    @Test
    void admissionAndSkipLinesMatchSpec() {
        Pvm2Admission a = new Pvm2Admission();
        a.noteCandidate();
        a.noteCandidate();
        a.noteCandidate();
        a.noteSuccess();
        a.noteFail("unsupported opcode 0x26");
        a.noteFail("too many regs");
        assertEquals(
                "PVM2 admission: candidates=3 attempted=3 success=1 fallback=2 rate=33.3%",
                a.admissionLine());
        assertEquals(
                "PVM2 skip reasons: unsupported_opcode=1 too_many_regs=1 try_catch=0 branch=0 type=0 other=0",
                a.skipReasonsLine());
        assertEquals(1, a.unsupportedOpcodes.get(0x26));
        assertEquals("TRUE_VMP unsupported opcodes (count): {0x26=1}",
                a.unsupportedOpcodesLine());
        assertTrue(a.admissionLine().startsWith("PVM2 admission:"));
        assertTrue(a.skipReasonsLine().startsWith("PVM2 skip reasons:"));
        assertEquals("TRUE_VMP unsupported opcodes (count): {}",
                new Pvm2Admission().unsupportedOpcodesLine());
    }
}
