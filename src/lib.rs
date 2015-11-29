extern crate crypto;

use std::hash::Hash;
use std::mem;
use std::slice;
use std::borrow::Borrow;
use std::ops::Deref;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::{Relaxed, SeqCst};
use std::sync::Mutex;
use std::collections::{hash_map, HashMap};

use crypto::sha1;
use crypto::digest::Digest;

#[derive(Clone, PartialEq, Eq, Hash)]
struct InternKey {
    data: [u32; 5],
}

impl InternKey {
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        let slice = &mut self.data[..];
        unsafe {
            let ptr: *mut u8 = mem::transmute(slice.as_ptr());
            slice::from_raw_parts_mut(ptr, 20)
        }
    }

    pub fn hash<T: ?Sized + Hash>(data: &T) -> InternKey {
        let mut hasher = sha1::Sha1::new();
        hasher.input_hashable(&data);
        let mut key = InternKey {
            data: unsafe { mem::uninitialized() },
        };
        hasher.result(key.as_slice_mut());
        key
    }
}

struct InternField<T> {
    count: AtomicUsize,
    data: T,
}

pub struct Interner<T> {
    map: Mutex<HashMap<InternKey, InternField<T>>>,
}

pub struct Interned<'a, T: 'a> {
    key: InternKey,
    interner: &'a Interner<T>,
    field: *const InternField<T>,
}

impl<T: Hash> Interner<T> {
    pub fn new() -> Interner<T> {
        Interner {
            map: Mutex::new(HashMap::new()),
        }
    }

    fn intern_with<'a, F: FnOnce() -> T>(&'a self, key: InternKey, f: F) -> Interned<'a, T> {
        let mut map = self.map.lock().unwrap();
        let entry = map.entry(key.clone());
        let field = match entry {
            hash_map::Entry::Occupied(oe) => oe.into_mut(),
            hash_map::Entry::Vacant(ve) => ve.insert(InternField {
                count: AtomicUsize::new(0),
                data: f(),
            }),
        };
        field.count.fetch_add(1, Relaxed);
        Interned {
            key: key,
            interner: self,
            field: field as *const InternField<T>,
        }
    }

    pub fn intern<'a>(&'a self, data: T) -> Interned<'a, T> {
        let key = InternKey::hash(&data);
        self.intern_with(key, || data)
    }

    pub fn intern_borrowed<'a, B: ?Sized>(&'a self, data: &B) -> Interned<'a, T>
            where B: Hash + ToOwned<Owned=T>,
                  T: Hash + Borrow<B>
    {
        let key = InternKey::hash(data);
        self.intern_with(key, || data.to_owned())
    }
}

impl<'a, T> Deref for Interned<'a, T> {
    type Target = T;

    fn deref<'b>(&'b self) -> &'b T {
        let field: &'b InternField<T> = unsafe { mem::transmute(self.field) };
        &field.data
    }
}

impl<'a, T> Drop for Interned<'a, T> {
    fn drop<'b>(&'b mut self) {
        let field: &'b InternField<T> = unsafe { mem::transmute(self.field) };
        if 1 == field.count.fetch_sub(1, Relaxed) {
            let mut map = self.interner.map.lock().unwrap();
            let entry = map.entry(self.key.clone());
            match entry {
                hash_map::Entry::Occupied(oe) => {
                    if 0 == oe.get().count.load(SeqCst) {
                        let _ = oe.remove();
                    }
                }
                hash_map::Entry::Vacant(_) => panic!("The Interned was not really interned!"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Interner;

    #[test]
    fn intern_strings() {
        let interner = Interner::new();
        let s0 = String::from("hello");
        let s0 = interner.intern(s0);
        let s1 = interner.intern_borrowed("hello");
        assert_eq!(*s0, "hello");
        assert_eq!(*s0, *s1);
    }
}

