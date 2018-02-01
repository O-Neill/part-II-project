package uk.ac.cam.bo271.applets.opacity_zkm_opt;

import javacard.framework.*;

// Class containing the Persistent Binding information.
public class PBReg {
    // Store ID_host to Z mapping.

    // TODO: possible optimization is to use Red-black tree instead of linked list.

    // TODO: Improve by storing pointers into a large array rather than having
    // lots of small arrays.
    // TODO: Make resilient to memory failure by constantly allocating memory in
    // list.
    class ListElem {
        private byte[] host_id;
        private byte[] secret;
        private ListElem next;

        public ListElem(byte[] id, byte[] z, short zOffset) {
            host_id = new byte[8];
            secret = new byte[32];
            Util.arrayCopy(id, (short)0, host_id, (short)0, (short)8);
            Util.arrayCopy(z, zOffset, secret, (short)0, (short)secret.length);

        }

        public byte compareWithHostID(byte[] other_id) {
            return Util.arrayCompare(other_id, (short)0, host_id, (short)0, (short)8);
        }
        public void getSecret(byte[] outArray, short outOffset) {
            Util.arrayCopy(secret, (short)0, outArray, outOffset, (short)secret.length);
        }
        public void setSecret(byte[] z, short zOffset) {
            Util.arrayCopy(z, zOffset, secret, (short)0, (short)secret.length);
        }

        public void setNext(ListElem newNext) {
            next = newNext;
        }

        public ListElem getNext() {
            return next;
        }

    }


    class List {
        private ListElem head;
        public short len = 0;

        public void insert(ListElem newElem) {
            if (head != null) {
                newElem.setNext(head);
            }
            head = newElem;
            len++;
        }

        public ListElem findElem(byte[] host_id) {
            ListElem curr = head;
            while (curr != null) {
                // If found set value and return true
                if (curr.compareWithHostID(host_id) == 0) {
                    return curr;
                }
                curr = curr.getNext();
            }
            return null;
        }


    }

    private List mapping;

    public PBReg() {
        mapping = new List();
    }

    // Returns true/false depending on whether match was found.
    public boolean getZ(byte[] host_id, byte[] zOut, short zOffset) {
        ListElem elem = mapping.findElem(host_id);
        if (elem == null) {
            return false;
        }
        elem.getSecret(zOut, zOffset);
        return true;
    }

    // If the requested ID already has an entry, update it with a new value,
    // otherwise create a new entry.
    public void add_or_update(byte[] host_id, byte[] z, short zOffset) {
        ListElem elem = mapping.findElem(host_id);
        if (elem == null) {
            elem = new ListElem(host_id, z, zOffset);
            mapping.insert(elem);
        } else {
            elem.setSecret(z, zOffset);
        }
    }

    public boolean registered(byte[] host_id) {
        ListElem elem = mapping.findElem(host_id);
        return (elem != null);
    }

}
